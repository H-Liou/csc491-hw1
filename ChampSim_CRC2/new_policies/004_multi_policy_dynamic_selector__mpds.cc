#include <vector>
#include <cstdint>
#include <iostream>
#include <algorithm>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- Policy IDs ---
enum PolicyType { POLICY_LRU = 0, POLICY_SRRIP = 1, POLICY_BIP = 2, POLICY_ADAPTIVE = 3 };
const uint32_t NUM_POLICIES = 3;

// --- Set-dueling: assign leader sets for policy selection ---
const uint32_t NUM_LEADER_SETS = 32; // 32 sets per policy as leader
std::vector<PolicyType> set_policy(LLC_SETS, POLICY_ADAPTIVE);

// --- Replacement state per block ---
struct BlockState {
    // LRU
    uint32_t lru_stack;
    // SRRIP
    uint8_t rrpv; // Re-reference Prediction Value (0=MRU, 3=long re-ref)
    // BIP
    // No per-block state needed
};

std::vector<std::vector<BlockState>> block_state(LLC_SETS, std::vector<BlockState>(LLC_WAYS));

// --- Policy leader stats ---
struct PolicyStats {
    uint64_t hits = 0;
    uint64_t misses = 0;
};
std::vector<PolicyStats> leader_stats(NUM_POLICIES);

// --- Global stats ---
uint64_t total_evictions = 0;

// --- Utility: assign leader sets for each policy ---
void InitLeaderSets() {
    // Evenly distribute leader sets for each policy
    for (uint32_t i = 0; i < NUM_LEADER_SETS * NUM_POLICIES; ++i) {
        uint32_t set = (i * LLC_SETS) / (NUM_LEADER_SETS * NUM_POLICIES);
        set_policy[set] = static_cast<PolicyType>(i / NUM_LEADER_SETS);
    }
}

// --- Initialize replacement state ---
void InitReplacementState() {
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            block_state[set][way] = {way, 3}; // LRU: stack pos, SRRIP: max RRPV
        }
    }
    leader_stats = std::vector<PolicyStats>(NUM_POLICIES);
    total_evictions = 0;
    InitLeaderSets();
}

// --- Policy selection: choose best policy based on leader stats ---
PolicyType GetBestPolicy() {
    uint64_t best_hits = 0;
    PolicyType best_policy = POLICY_LRU;
    for (uint32_t p = 0; p < NUM_POLICIES; ++p) {
        if (leader_stats[p].hits > best_hits) {
            best_hits = leader_stats[p].hits;
            best_policy = static_cast<PolicyType>(p);
        }
    }
    return best_policy;
}

// --- Find victim in the set ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    PolicyType policy = set_policy[set];
    if (policy == POLICY_ADAPTIVE)
        policy = GetBestPolicy();

    uint32_t victim = 0;
    switch (policy) {
        case POLICY_LRU: {
            // Evict block with highest LRU stack position
            uint32_t max_lru = 0;
            for (uint32_t way = 0; way < LLC_WAYS; ++way) {
                if (block_state[set][way].lru_stack >= max_lru) {
                    max_lru = block_state[set][way].lru_stack;
                    victim = way;
                }
            }
            break;
        }
        case POLICY_SRRIP: {
            // Evict block with RRPV==3 (long re-ref), else increment all and retry
            while (true) {
                for (uint32_t way = 0; way < LLC_WAYS; ++way) {
                    if (block_state[set][way].rrpv == 3) {
                        victim = way;
                        goto srrip_found;
                    }
                }
                // Increment all RRPVs
                for (uint32_t way = 0; way < LLC_WAYS; ++way)
                    block_state[set][way].rrpv = std::min(block_state[set][way].rrpv + 1, 3u);
            }
srrip_found:
            break;
        }
        case POLICY_BIP: {
            // BIP: Evict block with highest LRU stack position (like LRU)
            uint32_t max_lru = 0;
            for (uint32_t way = 0; way < LLC_WAYS; ++way) {
                if (block_state[set][way].lru_stack >= max_lru) {
                    max_lru = block_state[set][way].lru_stack;
                    victim = way;
                }
            }
            break;
        }
        default:
            // Fallback to LRU
            for (uint32_t way = 0; way < LLC_WAYS; ++way) {
                if (block_state[set][way].lru_stack >= block_state[set][victim].lru_stack)
                    victim = way;
            }
            break;
    }
    total_evictions++;
    return victim;
}

// --- Update replacement state ---
void UpdateReplacementState(
    uint32_t cpu,
    uint32_t set,
    uint32_t way,
    uint64_t paddr,
    uint64_t PC,
    uint64_t victim_addr,
    uint32_t type,
    uint8_t hit
) {
    PolicyType policy = set_policy[set];
    if (policy == POLICY_ADAPTIVE)
        policy = GetBestPolicy();

    // Update leader stats if this is a leader set
    if (policy != POLICY_ADAPTIVE) {
        if (hit)
            leader_stats[policy].hits++;
        else
            leader_stats[policy].misses++;
    }

    switch (policy) {
        case POLICY_LRU: {
            // Move accessed block to MRU, update stack positions
            uint32_t old_pos = block_state[set][way].lru_stack;
            for (uint32_t w = 0; w < LLC_WAYS; ++w) {
                if (block_state[set][w].lru_stack < old_pos)
                    block_state[set][w].lru_stack++;
            }
            block_state[set][way].lru_stack = 0;
            break;
        }
        case POLICY_SRRIP: {
            if (hit) {
                block_state[set][way].rrpv = 0; // promote to MRU
            } else {
                // On fill, insert with RRPV=2 (long re-ref), as in SRRIP
                block_state[set][way].rrpv = 2;
            }
            break;
        }
        case POLICY_BIP: {
            // BIP: On fill, insert mostly at LRU, sometimes at MRU (1/32 probability)
            static uint32_t bip_counter = 0;
            bool insert_mru = (bip_counter++ % 32 == 0);
            uint32_t old_pos = block_state[set][way].lru_stack;
            for (uint32_t w = 0; w < LLC_WAYS; ++w) {
                if (block_state[set][w].lru_stack < old_pos)
                    block_state[set][w].lru_stack++;
            }
            block_state[set][way].lru_stack = insert_mru ? 0 : (LLC_WAYS - 1);
            break;
        }
        default: {
            // Fallback to LRU
            uint32_t old_pos = block_state[set][way].lru_stack;
            for (uint32_t w = 0; w < LLC_WAYS; ++w) {
                if (block_state[set][w].lru_stack < old_pos)
                    block_state[set][w].lru_stack++;
            }
            block_state[set][way].lru_stack = 0;
            break;
        }
    }
}

// --- Print end-of-simulation statistics ---
void PrintStats() {
    std::cout << "MPDS: total_evictions=" << total_evictions << std::endl;
    std::cout << "Leader Policy Stats:" << std::endl;
    std::cout << "  LRU: hits=" << leader_stats[POLICY_LRU].hits << " misses=" << leader_stats[POLICY_LRU].misses << std::endl;
    std::cout << "  SRRIP: hits=" << leader_stats[POLICY_SRRIP].hits << " misses=" << leader_stats[POLICY_SRRIP].misses << std::endl;
    std::cout << "  BIP: hits=" << leader_stats[POLICY_BIP].hits << " misses=" << leader_stats[POLICY_BIP].misses << std::endl;
}

// --- Print periodic (heartbeat) statistics ---
void PrintStats_Heartbeat() {
    PrintStats();
}