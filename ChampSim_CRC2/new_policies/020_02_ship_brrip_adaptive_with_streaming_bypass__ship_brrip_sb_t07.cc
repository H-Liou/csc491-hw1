#include <vector>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- SHiP-lite: 5-bit PC signature per block, 2-bit outcome counter per signature ---
#define SIG_BITS 5
#define SIG_TABLE_SIZE 32
uint8_t block_sig[LLC_SETS][LLC_WAYS];       // Per-block signature (5 bits)
uint8_t sig_outcome[SIG_TABLE_SIZE];         // 2-bit saturating counter per signature

// --- RRIP metadata: 2-bit RRPV per block ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// --- Streaming detector: per-set, stride, monotonic counter (2 bits) ---
uint64_t last_addr[LLC_SETS];
int64_t last_stride[LLC_SETS];
uint8_t monotonic_count[LLC_SETS];
#define STREAM_THRESHOLD 2 // streaming if monotonic_count >= 2

// --- Set-dueling for SRRIP vs BRRIP, global PSEL (10 bits) ---
#define DUEL_LEADER_SETS 32
uint8_t is_brrip_leader[LLC_SETS]; // 1 if BRRIP leader, 0 if SRRIP leader, else follower
uint16_t PSEL = 512; // 10-bit, 0=SRRIP, 1023=BRRIP

// Helper: select leader sets (first 32 for SRRIP, next 32 for BRRIP)
void init_leader_sets() {
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        is_brrip_leader[set] = 0;
    for (uint32_t i = 0; i < DUEL_LEADER_SETS; ++i)
        is_brrip_leader[i] = 0; // SRRIP leaders
    for (uint32_t i = 0; i < DUEL_LEADER_SETS; ++i)
        is_brrip_leader[DUEL_LEADER_SETS + i] = 1; // BRRIP leaders
}

// Initialize replacement state
void InitReplacementState() {
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            rrpv[set][way] = 2;
            block_sig[set][way] = 0;
        }
        last_addr[set] = 0;
        last_stride[set] = 0;
        monotonic_count[set] = 0;
        is_brrip_leader[set] = 0;
    }
    for (int i = 0; i < SIG_TABLE_SIZE; ++i)
        sig_outcome[i] = 1;
    PSEL = 512;
    init_leader_sets();
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
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (rrpv[set][way] == 3)
                return way;
        }
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] < 3)
                ++rrpv[set][way];
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
    // --- Streaming detector update ---
    int64_t stride = (last_addr[set] == 0) ? 0 : int64_t(paddr) - int64_t(last_addr[set]);
    if (last_addr[set] != 0 && stride == last_stride[set] && stride != 0) {
        if (monotonic_count[set] < 3) monotonic_count[set]++;
    } else {
        if (monotonic_count[set] > 0) monotonic_count[set]--;
    }
    last_addr[set] = paddr;
    last_stride[set] = stride;

    // --- SHiP signature ---
    uint8_t sig = ((PC >> 2) ^ (set & 0x1F)) & ((1 << SIG_BITS) - 1);

    // --- Set-dueling update ---
    bool is_leader = (set < DUEL_LEADER_SETS * 2);
    if (is_leader) {
        // On hit, reward the policy of the leader set
        if (hit) {
            if (is_brrip_leader[set]) {
                if (PSEL < 1023) PSEL++;
            } else {
                if (PSEL > 0) PSEL--;
            }
        }
    }

    // --- Insertion logic ---
    bool stream_detected = (monotonic_count[set] >= STREAM_THRESHOLD);
    bool hot_sig = (sig_outcome[sig] >= 2);

    // On block fill (miss, replacement)
    if (!hit) {
        // Penalize signature outcome if victim not reused
        uint8_t victim_sig = block_sig[set][way];
        if (sig_outcome[victim_sig] > 0)
            sig_outcome[victim_sig]--;

        block_sig[set][way] = sig;

        // Streaming bypass logic
        if (stream_detected && !hot_sig) {
            rrpv[set][way] = 3; // bypass: insert as LRU
        } else {
            // Leader sets override insertion depth for set-dueling
            if (is_leader) {
                if (is_brrip_leader[set]) {
                    // BRRIP: insert at distant (RRPV=2/3, with 1/32 probability MRU)
                    if ((rand() & 0x1F) == 0)
                        rrpv[set][way] = 0;
                    else
                        rrpv[set][way] = 2 + (rand() & 0x1);
                } else {
                    // SRRIP: hot signature gets MRU, else distant
                    rrpv[set][way] = hot_sig ? 0 : 2;
                }
            } else {
                // Followers use global PSEL
                if (PSEL >= 512) {
                    // BRRIP: mostly distant, rare MRU
                    if ((rand() & 0x1F) == 0)
                        rrpv[set][way] = 0;
                    else
                        rrpv[set][way] = 2 + (rand() & 0x1);
                } else {
                    // SRRIP: hot signature gets MRU, else distant
                    rrpv[set][way] = hot_sig ? 0 : 2;
                }
            }
        }
    } else {
        // On hit, promote block, reward signature
        rrpv[set][way] = 0;
        if (sig_outcome[block_sig[set][way]] < 3)
            sig_outcome[block_sig[set][way]]++;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    int hot_sigs = 0, cold_sigs = 0;
    for (int i = 0; i < SIG_TABLE_SIZE; ++i) {
        if (sig_outcome[i] >= 2) hot_sigs++;
        else cold_sigs++;
    }
    std::cout << "SHiP-BRRIP-SB: Hot signatures: " << hot_sigs
              << " / " << SIG_TABLE_SIZE << std::endl;
    std::cout << "SHiP-BRRIP-SB: Cold signatures: " << cold_sigs << std::endl;

    int streaming_sets = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        if (monotonic_count[set] >= STREAM_THRESHOLD) streaming_sets++;
    std::cout << "SHiP-BRRIP-SB: Streaming sets: " << streaming_sets
              << " / " << LLC_SETS << std::endl;

    std::cout << "SHiP-BRRIP-SB: Global PSEL = " << PSEL << " (SRRIP<512<BRRIP)" << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    int streaming_sets = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        if (monotonic_count[set] >= STREAM_THRESHOLD) streaming_sets++;
    std::cout << "SHiP-BRRIP-SB: Streaming sets: " << streaming_sets << std::endl;
    std::cout << "SHiP-BRRIP-SB: Global PSEL = " << PSEL << std::endl;
}