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

// DIP-style leader sets: 64 sets, half for SRRIP, half for BRRIP
#define NUM_LEADER_SETS 64
#define PSEL_BITS 10
uint16_t PSEL = 1 << (PSEL_BITS - 1); // 10-bit saturating counter

// Streaming detector: last address and delta per set, 2-bit confidence
struct StreamDetect {
    uint64_t last_addr;
    int64_t last_delta;
    uint8_t stream_conf; // 2 bits
};
StreamDetect stream_meta[LLC_SETS];

// Helper: leader set mapping
inline bool is_leader_set(uint32_t set, bool &is_srrip_leader, bool &is_brrip_leader) {
    // Use lower 6 bits for 64 leader sets
    uint32_t lset = set & (NUM_LEADER_SETS - 1);
    is_srrip_leader = (lset < NUM_LEADER_SETS / 2);
    is_brrip_leader = (lset >= NUM_LEADER_SETS / 2);
    return is_srrip_leader || is_brrip_leader;
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
    PSEL = 1 << (PSEL_BITS - 1);
}

// Find victim in the set (prefer invalid, then RRIP)
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

    // 2. RRIP victim search
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
    // --- Streaming detector update ---
    bool is_stream = IsStreaming(set, paddr);

    // --- DIP leader set selection ---
    bool is_srrip_leader = false, is_brrip_leader = false;
    bool is_leader = is_leader_set(set, is_srrip_leader, is_brrip_leader);

    // --- On hit: promote to MRU ---
    if (hit) {
        meta[set][way].rrpv = 0;
        // Update PSEL for leader sets
        if (is_leader) {
            if (is_srrip_leader && PSEL < ((1 << PSEL_BITS) - 1)) PSEL++;
            if (is_brrip_leader && PSEL > 0) PSEL--;
        }
        return;
    }

    // --- On miss/fill: choose insertion depth ---
    if (is_stream) {
        // Streaming: bypass (do not insert) if possible, else insert at distant RRPV
        // Champsim: must insert if all blocks valid, so insert at distant RRPV
        meta[set][way].rrpv = 3;
        return;
    }

    // DRRIP insertion policy
    uint8_t ins_rrpv = 2; // SRRIP: insert at distant (2)
    // BRRIP: insert at MRU (0) with low probability (1/32), else at distant (2)
    bool use_brrip = false;
    if (!is_leader) {
        use_brrip = (PSEL < (1 << (PSEL_BITS - 1)));
    } else {
        use_brrip = is_brrip_leader;
    }
    if (use_brrip) {
        // 1/32 probability for MRU, else distant
        if ((rand() & 31) == 0)
            ins_rrpv = 0;
        else
            ins_rrpv = 2;
    }
    meta[set][way].rrpv = ins_rrpv;
}

// Print end-of-simulation statistics
void PrintStats() {
    // Print streaming set count and PSEL value
    uint32_t stream_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (stream_meta[s].stream_conf >= 2) stream_sets++;
    std::cout << "DRRIP-SB-DIP: streaming sets=" << stream_sets << "/" << LLC_SETS
              << ", PSEL=" << PSEL << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // No periodic decay needed
}