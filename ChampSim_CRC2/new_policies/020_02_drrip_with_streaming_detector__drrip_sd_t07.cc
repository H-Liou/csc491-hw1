#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// DRRIP: 2-bit RRPV, 10-bit PSEL, 32 leader sets for SRRIP/BRRIP
#define PSEL_BITS 10
#define LEADER_SETS 32

uint16_t PSEL = (1 << (PSEL_BITS - 1)); // Start neutral
bool is_srrip_leader[LLC_SETS] = {0};
bool is_brrip_leader[LLC_SETS] = {0};

struct BlockMeta {
    uint8_t rrpv; // 2 bits
};
BlockMeta meta[LLC_SETS][LLC_WAYS];

// Streaming detector: 4 bits per set (tracks delta monotonicity)
struct StreamSetMeta {
    uint64_t last_addr;
    int64_t last_delta;
    uint8_t stream_score; // 4 bits: saturating counter
};
StreamSetMeta sstream[LLC_SETS];

// Helper: assign leader sets at startup
void InitLeaderSets() {
    // First LEADER_SETS are SRRIP, next LEADER_SETS are BRRIP
    for (uint32_t i = 0; i < LEADER_SETS; ++i)
        is_srrip_leader[i] = true;
    for (uint32_t i = LEADER_SETS; i < 2*LEADER_SETS; ++i)
        is_brrip_leader[i] = true;
}

// Initialize replacement state
void InitReplacementState() {
    memset(meta, 0, sizeof(meta));
    memset(sstream, 0, sizeof(sstream));
    InitLeaderSets();
    PSEL = (1 << (PSEL_BITS - 1));
}

// Find victim in the set (RRIP)
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Prefer invalid blocks
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (!current_set[way].valid)
            return way;

    // RRIP victim selection
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (meta[set][way].rrpv == 3)
                return way;
        // Increment RRPV for all blocks
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (meta[set][way].rrpv < 3)
                meta[set][way].rrpv++;
    }
    return 0; // Should not reach
}

// Streaming detector logic
bool IsStreaming(uint32_t set, uint64_t paddr) {
    StreamSetMeta &ss = sstream[set];
    int64_t delta = (int64_t)paddr - (int64_t)ss.last_addr;
    bool streaming = false;
    if (ss.last_addr != 0) {
        if (delta == ss.last_delta && delta != 0) {
            // Monotonic stride detected
            if (ss.stream_score < 15) ss.stream_score++;
        } else {
            if (ss.stream_score > 0) ss.stream_score--;
        }
        streaming = (ss.stream_score >= 8);
    }
    ss.last_delta = delta;
    ss.last_addr = paddr;
    return streaming;
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
    // Streaming detector update
    bool streaming = IsStreaming(set, paddr);

    // On hit: promote to MRU (RRPV=0)
    if (hit) {
        meta[set][way].rrpv = 0;
        return;
    }

    // On fill: choose RRIP insertion policy
    uint8_t ins_rrpv = 2; // default distant for BRRIP
    bool use_srrip = false;
    if (is_srrip_leader[set]) {
        // SRRIP leader: always insert MRU (RRPV=0)
        ins_rrpv = 0;
        use_srrip = true;
    } else if (is_brrip_leader[set]) {
        // BRRIP leader: mostly distant (RRPV=2), occasionally MRU
        ins_rrpv = ((rand() & 0x1F) == 0) ? 0 : 2; // 1/32 MRU
        use_srrip = false;
    } else {
        // Non-leader: policy picked by PSEL
        if (PSEL >= (1 << (PSEL_BITS-1))) {
            // SRRIP: insert MRU
            ins_rrpv = 0;
            use_srrip = true;
        } else {
            // BRRIP: mostly distant
            ins_rrpv = ((rand() & 0x1F) == 0) ? 0 : 2;
            use_srrip = false;
        }
    }

    // Streaming: force distant (RRPV=3) or bypass
    if (streaming) {
        ins_rrpv = 3; // insert at most distant position
        // Optionally: bypass (do not cache) if ALL lines valid and RRPVs are high
        bool all_rrpv_high = true;
        for (uint32_t w = 0; w < LLC_WAYS; ++w)
            if (meta[set][w].rrpv < 2)
                all_rrpv_high = false;
        if (all_rrpv_high) {
            // Do not install; let victim remain (simulates bypass)
            return;
        }
    }

    meta[set][way].rrpv = ins_rrpv;

    // Update PSEL for leader sets
    if (is_srrip_leader[set]) {
        if (hit && PSEL < ((1 << PSEL_BITS) - 1)) PSEL++;
    } else if (is_brrip_leader[set]) {
        if (hit && PSEL > 0) PSEL--;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "DRRIP-SD: Final PSEL = " << PSEL << std::endl;
    uint64_t rrpv_hist[4] = {0};
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        for (uint32_t w = 0; w < LLC_WAYS; ++w)
            rrpv_hist[meta[s][w].rrpv]++;
    std::cout << "DRRIP-SD: RRPV histogram: ";
    for (int i = 0; i < 4; ++i)
        std::cout << rrpv_hist[i] << " ";
    std::cout << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // No periodic decay needed
}