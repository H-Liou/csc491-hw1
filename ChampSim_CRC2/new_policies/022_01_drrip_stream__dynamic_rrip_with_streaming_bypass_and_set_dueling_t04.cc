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

// Streaming detector: last address, last delta, 2-bit confidence per set
struct StreamDetect {
    uint64_t last_addr;
    int64_t last_delta;
    uint8_t stream_conf; // 2 bits
};
StreamDetect stream_meta[LLC_SETS];

// DRRIP set-dueling: 64 leader sets for SRRIP, 64 for BRRIP
#define NUM_LEADER_SETS 64
std::vector<uint32_t> leader_srrip;
std::vector<uint32_t> leader_brrip;

// PSEL: 10-bit global selector
uint16_t PSEL = 512;

// Helper: assign leader sets deterministically
void InitLeaderSets() {
    leader_srrip.clear();
    leader_brrip.clear();
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i) {
        leader_srrip.push_back(i);
        leader_brrip.push_back(i + LLC_SETS/2);
    }
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
    InitLeaderSets();
    PSEL = 512;
}

// Find victim in the set (prefer invalid, else RRPV==3)
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (!current_set[way].valid)
            return way;
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
    // --- Streaming detector ---
    bool is_stream = IsStreaming(set, paddr);

    // --- DRRIP set-dueling: choose insertion policy ---
    bool is_leader_sr = false, is_leader_br = false;
    for (auto s : leader_srrip) if (set == s) is_leader_sr = true;
    for (auto s : leader_brrip) if (set == s) is_leader_br = true;

    uint8_t ins_rrpv = 3; // default distant

    if (is_stream) {
        // Streaming: bypass (do not insert) if possible, else insert at distant
        ins_rrpv = 3;
    } else if (is_leader_sr) {
        ins_rrpv = 2; // SRRIP leader: insert at RRPV=2 (aggressive)
    } else if (is_leader_br) {
        ins_rrpv = (rand() % 32 == 0) ? 2 : 3; // BRRIP leader: mostly distant, 1/32 at RRPV=2
    } else {
        // Normal sets: pick policy based on PSEL
        if (PSEL >= 512)
            ins_rrpv = 2; // SRRIP
        else
            ins_rrpv = (rand() % 32 == 0) ? 2 : 3; // BRRIP
    }

    // --- On hit: promote to MRU
    if (hit) {
        meta[set][way].rrpv = 0;
        // Update PSEL for leader sets
        if (is_leader_sr && PSEL < 1023) PSEL++;
        if (is_leader_br && PSEL > 0) PSEL--;
        return;
    }

    // --- On miss/fill: set insertion RRPV
    meta[set][way].rrpv = ins_rrpv;
}

// Print end-of-simulation statistics
void PrintStats() {
    uint32_t stream_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (stream_meta[s].stream_conf >= 2) stream_sets++;
    std::cout << "DRRIP-Stream: streaming sets=" << stream_sets << "/" << LLC_SETS
              << ", PSEL=" << PSEL << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // No periodic decay needed
}