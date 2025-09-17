#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// DRRIP: 2-bit RRPV per block, set-dueling with 64 leader sets, 10-bit PSEL
#define RRPV_BITS 2
#define RRPV_MAX ((1 << RRPV_BITS) - 1)
#define NUM_LEADER_SETS 64
#define PSEL_BITS 10
uint16_t PSEL = (1 << (PSEL_BITS - 1)); // Centered

// Streaming detector: last address and delta per set (simple monotonic stream detector)
struct StreamDetect {
    uint64_t last_addr;
    int64_t last_delta;
    uint8_t stream_conf; // 2 bits, saturating
};
StreamDetect stream_meta[LLC_SETS];

// Per-block metadata: RRPV (2 bits), dead-counter (2 bits)
struct BlockMeta {
    uint8_t rrpv;      // 2 bits
    uint8_t dead_ctr;  // 2 bits
};
BlockMeta meta[LLC_SETS][LLC_WAYS];

// Helper: Is this set a DRRIP leader set? (first NUM_LEADER_SETS for SRRIP, next NUM_LEADER_SETS for BRRIP)
inline bool is_leader_set(uint32_t set, bool &is_srrip, bool &is_brrip) {
    is_srrip = (set < NUM_LEADER_SETS);
    is_brrip = (set >= NUM_LEADER_SETS && set < 2 * NUM_LEADER_SETS);
    return is_srrip || is_brrip;
}

// Streaming detector: returns true if stream detected in this set
inline bool IsStreaming(uint32_t set, uint64_t paddr) {
    StreamDetect &sd = stream_meta[set];
    int64_t delta = paddr - sd.last_addr;
    bool is_stream = false;
    if (sd.last_addr != 0) {
        if (delta == sd.last_delta && delta != 0) {
            if (sd.stream_conf < 3) sd.stream_conf++;
        } else {
            if (sd.stream_conf > 0) sd.stream_conf--;
        }
        if (sd.stream_conf >= 2) is_stream = true;
    }
    sd.last_delta = delta;
    sd.last_addr = paddr;
    return is_stream;
}

// Initialize replacement state
void InitReplacementState() {
    memset(meta, 0, sizeof(meta));
    memset(stream_meta, 0, sizeof(stream_meta));
    PSEL = (1 << (PSEL_BITS - 1));
}

// Find victim in the set (prefer invalid, then dead blocks, then RRIP)
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // 1. Prefer invalid blocks
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (!current_set[way].valid)
            return way;

    // 2. Prefer dead blocks (dead_ctr==0)
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (meta[set][way].dead_ctr == 0)
            return way;

    // 3. RRIP victim search
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (meta[set][way].rrpv == RRPV_MAX)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (meta[set][way].rrpv < RRPV_MAX)
                meta[set][way].rrpv++;
    }
    return 0; // Should not reach
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
    bool is_stream = IsStreaming(set, paddr);

    // --- DRRIP set-dueling: determine insertion policy ---
    bool is_srrip = false, is_brrip = false;
    bool leader = is_leader_set(set, is_srrip, is_brrip);

    // --- On hit: promote to MRU, reset dead-counter ---
    if (hit) {
        meta[set][way].rrpv = 0;
        meta[set][way].dead_ctr = 3;
        // Update PSEL for leader sets
        if (leader) {
            if (is_srrip && PSEL < ((1 << PSEL_BITS) - 1)) PSEL++;
            if (is_brrip && PSEL > 0) PSEL--;
        }
        return;
    }

    // --- On miss/fill: choose insertion depth ---
    uint8_t ins_rrpv = RRPV_MAX; // Default: distant
    if (is_stream) {
        // Streaming: bypass (do not insert) if possible, else insert at distant RRPV
        ins_rrpv = RRPV_MAX;
    } else if (leader) {
        // Leader sets: SRRIP or BRRIP
        ins_rrpv = is_srrip ? 2 : (rand() % 32 == 0 ? 2 : 3); // SRRIP: 2, BRRIP: 2 with 1/32, else 3
    } else {
        // Follower sets: use PSEL
        ins_rrpv = (PSEL >= (1 << (PSEL_BITS - 1))) ? 2 : (rand() % 32 == 0 ? 2 : 3);
    }
    meta[set][way].rrpv = ins_rrpv;
    meta[set][way].dead_ctr = 3; // Assume live on fill

    // --- On victim: nothing to update for DRRIP

    // --- Dead-block decay is handled in heartbeat ---
}

// Print end-of-simulation statistics
void PrintStats() {
    // Print PSEL value and streaming detector histogram
    uint32_t stream_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (stream_meta[s].stream_conf >= 2) stream_sets++;
    std::cout << "DRRIP-SBD: PSEL=" << PSEL << ", streaming sets=" << stream_sets << "/" << LLC_SETS << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Periodic decay: age dead-counters
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        for (uint32_t w = 0; w < LLC_WAYS; ++w)
            if (meta[s][w].dead_ctr > 0)
                meta[s][w].dead_ctr--;
}