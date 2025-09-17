#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// DRRIP: 2-bit RRPV per block
struct BlockMeta {
    uint8_t rrpv; // 2 bits
};
BlockMeta meta[LLC_SETS][LLC_WAYS];

// DRRIP set-dueling: 64 leader sets for SRRIP, 64 for BRRIP
#define NUM_LEADER_SETS 64
#define PSEL_BITS 10
uint16_t PSEL = 1 << (PSEL_BITS - 1); // 10-bit PSEL, initialized to midpoint

// Streaming detector: 1 byte per set (tracks last address delta and streaming count)
struct StreamDetect {
    int64_t last_delta;
    uint8_t stream_count;
};
StreamDetect stream_meta[LLC_SETS];

// Helper: leader set mapping
inline bool IsSRRIPLeader(uint32_t set) { return set < NUM_LEADER_SETS; }
inline bool IsBRRIPLeader(uint32_t set) { return set >= LLC_SETS - NUM_LEADER_SETS; }

// Helper: streaming detection threshold
#define STREAM_THRESH 6

// Initialize replacement state
void InitReplacementState() {
    memset(meta, 0, sizeof(meta));
    memset(stream_meta, 0, sizeof(stream_meta));
    PSEL = 1 << (PSEL_BITS - 1);
}

// Find victim in the set (standard RRIP)
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

    // 2. RRIP victim search (find RRPV==3)
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (meta[set][way].rrpv == 3)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (meta[set][way].rrpv < 3)
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
    // --- Streaming detector: update per-set ---
    int64_t cur_delta = int64_t(paddr) - int64_t(stream_meta[set].last_delta);
    if (stream_meta[set].last_delta != 0 && std::abs(cur_delta) < 256) {
        // Near-monotonic stride detected
        if (cur_delta == stream_meta[set].last_delta)
            stream_meta[set].stream_count++;
        else
            stream_meta[set].stream_count = 0;
    } else {
        stream_meta[set].stream_count = 0;
    }
    stream_meta[set].last_delta = int64_t(paddr);

    // --- On hit: promote to MRU ---
    if (hit) {
        meta[set][way].rrpv = 0;
        return;
    }

    // --- Streaming bypass: if streaming detected, insert at distant RRPV or bypass ---
    bool is_streaming = (stream_meta[set].stream_count >= STREAM_THRESH);

    // DRRIP insertion policy
    uint8_t ins_rrpv = 2; // default SRRIP (insert at RRPV=2)
    if (IsSRRIPLeader(set)) {
        ins_rrpv = 2; // SRRIP leader: always insert at 2
    } else if (IsBRRIPLeader(set)) {
        ins_rrpv = (rand() % 32 == 0) ? 2 : 3; // BRRIP leader: insert at 2 with 1/32 probability, else 3
    } else {
        // Follower sets: use PSEL to choose
        if (PSEL >= (1 << (PSEL_BITS - 1)))
            ins_rrpv = 2; // SRRIP
        else
            ins_rrpv = (rand() % 32 == 0) ? 2 : 3; // BRRIP
    }

    // Streaming: if detected, insert at distant RRPV or bypass
    if (is_streaming) {
        ins_rrpv = 3; // Insert at distant RRPV
        // Optionally, bypass: do not update block meta (simulate bypass)
        // return; // Uncomment to enable full bypass
    }

    meta[set][way].rrpv = ins_rrpv;

    // --- DRRIP set-dueling: update PSEL ---
    if (!hit) {
        if (IsSRRIPLeader(set) && ins_rrpv == 2)
            if (PSEL < ((1 << PSEL_BITS) - 1)) PSEL++;
        if (IsBRRIPLeader(set) && ins_rrpv == 3)
            if (PSEL > 0) PSEL--;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "DRRIP-SB: PSEL=" << PSEL << std::endl;
    // Streaming histogram
    uint64_t stream_hist[16] = {0};
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        stream_hist[std::min(15u, stream_meta[s].stream_count)]++;
    std::cout << "DRRIP-SB: Streaming count histogram: ";
    for (int i = 0; i < 16; ++i)
        std::cout << stream_hist[i] << " ";
    std::cout << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Optionally, decay streaming counts
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (stream_meta[s].stream_count > 0)
            stream_meta[s].stream_count--;
}