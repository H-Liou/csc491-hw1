#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// RRIP constants
const uint8_t RRIP_MAX = 3;
const uint8_t RRIP_MRU = 0;
const uint8_t RRIP_DISTANT = 2;

// DRRIP set-dueling
const uint32_t NUM_LEADER_SETS = 64;
const uint32_t SRRIP_LEADER_SETS = NUM_LEADER_SETS / 2;
const uint32_t BRRIP_LEADER_SETS = NUM_LEADER_SETS / 2;
const uint32_t LEADER_SET_STRIDE = LLC_SETS / NUM_LEADER_SETS;

// PSEL selector
uint16_t PSEL = 512; // 10 bits, midpoint

// Per-block metadata: RRPV
uint8_t block_rrpv[LLC_SETS][LLC_WAYS];

// Per-set phase reuse counter (2 bits/set)
uint8_t set_reuse[LLC_SETS];

// Streaming detector: 3 bits/set
struct DSSPA_StreamSet {
    uint64_t last_addr;
    uint8_t stride_count; // up to 3
    uint8_t streaming;    // 1 if streaming detected
    uint8_t window;       // streaming window countdown
};
DSSPA_StreamSet stream_sets[LLC_SETS];

// Stats for periodic decay
uint64_t access_counter = 0;
const uint64_t DECAY_INTERVAL = 500000;  // every 500K accesses

// Streaming window length
const uint8_t STREAM_WIN = 8;

// Helper: leader set identification
inline bool is_srrip_leader(uint32_t set) {
    return (set % LEADER_SET_STRIDE) < (SRRIP_LEADER_SETS / (LLC_SETS / NUM_LEADER_SETS));
}
inline bool is_brrip_leader(uint32_t set) {
    return ((set + LEADER_SET_STRIDE/2) % LEADER_SET_STRIDE) < (BRRIP_LEADER_SETS / (LLC_SETS / NUM_LEADER_SETS));
}

// Initialize replacement state
void InitReplacementState() {
    memset(block_rrpv, RRIP_MAX, sizeof(block_rrpv));
    memset(set_reuse, 2, sizeof(set_reuse));
    memset(stream_sets, 0, sizeof(stream_sets));
    PSEL = 512;
    access_counter = 0;
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
    // Streaming: if active, always evict LRU (highest RRPV)
    if (stream_sets[set].streaming && stream_sets[set].window > 0) {
        uint32_t lru_way = 0;
        uint8_t max_rrpv = 0;
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (block_rrpv[set][way] >= max_rrpv) {
                max_rrpv = block_rrpv[set][way];
                lru_way = way;
            }
        }
        return lru_way;
    }

    // Standard RRIP victim selection
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (block_rrpv[set][way] == RRIP_MAX)
                return way;
        }
        // Increment all RRPVs
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (block_rrpv[set][way] < RRIP_MAX)
                block_rrpv[set][way]++;
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
    access_counter++;

    // --- Streaming detector ---
    DSSPA_StreamSet &ss = stream_sets[set];
    uint64_t cur_addr = paddr >> 6; // cache line granularity
    int64_t stride = cur_addr - ss.last_addr;
    if (ss.last_addr != 0 && (stride == 1 || stride == -1)) {
        if (ss.stride_count < 3) ss.stride_count++;
        if (ss.stride_count == 3 && !ss.streaming) {
            ss.streaming = 1;
            ss.window = STREAM_WIN;
        }
    } else {
        ss.stride_count = 0;
        ss.streaming = 0;
        ss.window = 0;
    }
    ss.last_addr = cur_addr;
    if (ss.streaming && ss.window > 0)
        ss.window--;

    // --- Per-set reuse counter decay (periodic) ---
    if ((access_counter % DECAY_INTERVAL) == 0) {
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            if (set_reuse[s] > 0)
                set_reuse[s]--;
    }

    // --- On hit ---
    if (hit) {
        block_rrpv[set][way] = RRIP_MRU;
        if (set_reuse[set] < 3)
            set_reuse[set]++;
    }
    // --- On miss (new insertion) ---
    else {
        // DRRIP set-dueling: choose insertion policy
        bool srrip_leader = is_srrip_leader(set);
        bool brrip_leader = is_brrip_leader(set);
        uint8_t ins_rrpv;
        if (stream_sets[set].streaming && stream_sets[set].window > 0) {
            // Streaming: bypass (insert as LRU)
            ins_rrpv = RRIP_MAX;
        } else if (srrip_leader) {
            ins_rrpv = RRIP_DISTANT;
        } else if (brrip_leader) {
            ins_rrpv = (rand() % 32 == 0) ? RRIP_DISTANT : RRIP_MAX; // BRRIP: 1/32 distant, else LRU
        } else {
            // Non-leader: use PSEL
            if (PSEL >= 512)
                ins_rrpv = RRIP_DISTANT;
            else
                ins_rrpv = (rand() % 32 == 0) ? RRIP_DISTANT : RRIP_MAX;
        }
        // Phase-adaptive: if set reuse counter is low, bias toward distant
        if (set_reuse[set] <= 1)
            ins_rrpv = RRIP_MAX;

        block_rrpv[set][way] = ins_rrpv;

        // Update PSEL for leader sets
        if (srrip_leader && hit)
            if (PSEL < 1023) PSEL++;
        if (brrip_leader && hit)
            if (PSEL > 0) PSEL--;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    // Streaming set count
    uint64_t streaming_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (stream_sets[s].streaming)
            streaming_sets++;
    std::cout << "DSSPA: Streaming sets at end: " << streaming_sets << std::endl;

    // Average set reuse
    uint64_t total_reuse = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        total_reuse += set_reuse[s];
    std::cout << "DSSPA: Average set reuse at end: " << (double(total_reuse) / LLC_SETS) << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Optionally print streaming window stats or set reuse ratio
}