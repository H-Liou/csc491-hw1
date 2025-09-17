#include <vector>
#include <cstdint>
#include <iostream>
#include <array>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- SRRIP parameters ---
constexpr uint8_t SRRIP_BITS = 2;
constexpr uint8_t SRRIP_MAX = (1 << SRRIP_BITS) - 1; // 3
constexpr uint8_t SRRIP_INSERT = SRRIP_MAX - 1;      // 2

// --- Set Dueling parameters ---
constexpr uint32_t NUM_LEADER_SETS = 64; // 32 for SRRIP leader, 32 for FIFO leader
constexpr uint32_t SRRIP_LEADER_SETS = NUM_LEADER_SETS / 2;
constexpr uint32_t FIFO_LEADER_SETS = NUM_LEADER_SETS / 2;

// --- Policy selection ---
enum PolicyType { POLICY_SRRIP = 0, POLICY_FIFO = 1 };

// --- Per-line metadata ---
struct LineMeta {
    uint64_t tag;
    uint8_t rrip; // Used for SRRIP
    uint32_t fifo_age; // Used for FIFO
};

// --- Per-set metadata ---
struct SetMeta {
    PolicyType policy;
    bool is_leader;
    PolicyType leader_type; // Only relevant if is_leader==true
};

// --- Global statistics for leader sets ---
struct LeaderStats {
    uint64_t hits;
    uint64_t accesses;
};

std::array<std::array<LineMeta, LLC_WAYS>, LLC_SETS> line_meta;
std::array<SetMeta, LLC_SETS> set_meta;
LeaderStats srrip_leader_stats = {0, 0};
LeaderStats fifo_leader_stats = {0, 0};
uint64_t global_hits = 0, global_misses = 0;

// Helper: select leader sets using simple hash
bool IsSRRIPLeaderSet(uint32_t set) {
    // Use first SRRIP_LEADER_SETS sets as SRRIP leaders
    return set < SRRIP_LEADER_SETS;
}
bool IsFIFOLeaderSet(uint32_t set) {
    // Next FIFO_LEADER_SETS sets as FIFO leaders
    return set >= SRRIP_LEADER_SETS && set < NUM_LEADER_SETS;
}

// Initialize replacement state
void InitReplacementState() {
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            line_meta[set][way] = {0, SRRIP_MAX, 0};
        }
        // Set leader/follower status
        if (IsSRRIPLeaderSet(set)) {
            set_meta[set] = {POLICY_SRRIP, true, POLICY_SRRIP};
        } else if (IsFIFOLeaderSet(set)) {
            set_meta[set] = {POLICY_FIFO, true, POLICY_FIFO};
        } else {
            set_meta[set] = {POLICY_SRRIP, false, POLICY_SRRIP}; // Default to SRRIP
        }
    }
    srrip_leader_stats = {0, 0};
    fifo_leader_stats = {0, 0};
    global_hits = global_misses = 0;
}

// Find victim in the set
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    PolicyType policy = set_meta[set].policy;
    if (set_meta[set].is_leader) {
        policy = set_meta[set].leader_type;
    }

    if (policy == POLICY_SRRIP) {
        // SRRIP: Find RRIP_MAX, else increment all and repeat
        while (true) {
            for (uint32_t w = 0; w < LLC_WAYS; ++w) {
                if (line_meta[set][w].rrip == SRRIP_MAX)
                    return w;
            }
            for (uint32_t w = 0; w < LLC_WAYS; ++w)
                if (line_meta[set][w].rrip < SRRIP_MAX)
                    line_meta[set][w].rrip++;
        }
    } else { // POLICY_FIFO
        // FIFO: Evict the line with the highest fifo_age
        uint32_t victim = 0;
        uint32_t max_age = line_meta[set][0].fifo_age;
        for (uint32_t w = 1; w < LLC_WAYS; ++w) {
            if (line_meta[set][w].fifo_age > max_age) {
                max_age = line_meta[set][w].fifo_age;
                victim = w;
            }
        }
        return victim;
    }
}

// Update replacement state
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
    PolicyType policy = set_meta[set].policy;
    if (set_meta[set].is_leader) {
        policy = set_meta[set].leader_type;
    }

    // Update global stats
    if (hit) global_hits++; else global_misses++;

    // Update leader stats
    if (set_meta[set].is_leader) {
        if (policy == POLICY_SRRIP) {
            srrip_leader_stats.accesses++;
            if (hit) srrip_leader_stats.hits++;
        } else {
            fifo_leader_stats.accesses++;
            if (hit) fifo_leader_stats.hits++;
        }
    }

    // Follower sets: periodically update policy based on leader stats
    if (!set_meta[set].is_leader && (global_hits + global_misses) % 4096 == 0) {
        double srrip_hit_rate = srrip_leader_stats.accesses ? (double)srrip_leader_stats.hits / srrip_leader_stats.accesses : 0.0;
        double fifo_hit_rate = fifo_leader_stats.accesses ? (double)fifo_leader_stats.hits / fifo_leader_stats.accesses : 0.0;
        set_meta[set].policy = (srrip_hit_rate >= fifo_hit_rate) ? POLICY_SRRIP : POLICY_FIFO;
    }

    // Update per-line metadata
    if (policy == POLICY_SRRIP) {
        if (hit) {
            line_meta[set][way].rrip = 0; // Promote on hit
            line_meta[set][way].tag = paddr >> 6;
        } else {
            line_meta[set][way].rrip = SRRIP_INSERT; // Insert
            line_meta[set][way].tag = paddr >> 6;
        }
        // FIFO age not used for SRRIP
        line_meta[set][way].fifo_age = 0;
    } else { // POLICY_FIFO
        // On hit: reset age
        if (hit) {
            line_meta[set][way].fifo_age = 0;
            line_meta[set][way].tag = paddr >> 6;
        } else {
            // On miss: insert with age 0, increment all other ages
            for (uint32_t w = 0; w < LLC_WAYS; ++w) {
                if (w == way) {
                    line_meta[set][w].fifo_age = 0;
                    line_meta[set][w].tag = paddr >> 6;
                } else {
                    if (line_meta[set][w].fifo_age < 0xFFFFFFFF)
                        line_meta[set][w].fifo_age++;
                }
            }
            // RRIP not used for FIFO
            line_meta[set][way].rrip = SRRIP_MAX;
        }
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "SRRIP-FIFO-DSD Policy: Total Hits = " << global_hits
              << ", Total Misses = " << global_misses << std::endl;
    std::cout << "Hit Rate = "
              << (100.0 * global_hits / (global_hits + global_misses)) << "%" << std::endl;
    std::cout << "SRRIP Leader Hit Rate: "
              << (srrip_leader_stats.accesses ? 100.0 * srrip_leader_stats.hits / srrip_leader_stats.accesses : 0.0) << "%" << std::endl;
    std::cout << "FIFO Leader Hit Rate: "
              << (fifo_leader_stats.accesses ? 100.0 * fifo_leader_stats.hits / fifo_leader_stats.accesses : 0.0) << "%" << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    std::cout << "[SRRIP-FIFO-DSD Heartbeat] Hits: " << global_hits
              << ", Misses: " << global_misses << std::endl;
    std::cout << "[SRRIP Leader] Hits: " << srrip_leader_stats.hits
              << ", Accesses: " << srrip_leader_stats.accesses << std::endl;
    std::cout << "[FIFO Leader] Hits: " << fifo_leader_stats.hits
              << ", Accesses: " << fifo_leader_stats.accesses << std::endl;
}