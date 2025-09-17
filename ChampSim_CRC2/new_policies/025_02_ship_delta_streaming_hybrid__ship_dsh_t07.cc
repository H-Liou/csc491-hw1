#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// SHiP-lite: 4-bit PC signature per block, global SHCT[16K] x 2 bits
struct BlockMeta {
    uint8_t rrpv;         // 2 bits
    uint8_t sig;          // 4 bits compressed PC signature
};
BlockMeta meta[LLC_SETS][LLC_WAYS];

// SHCT: 16K entries × 2 bits
#define SHCT_SIZE 16384
uint8_t SHCT[SHCT_SIZE];

// DIP: leader sets for SRRIP/BRRIP
#define NUM_LEADER_SETS 64
std::vector<uint32_t> leader_srrip;
std::vector<uint32_t> leader_brrip;

// PSEL: 10 bits
uint16_t PSEL = 512;

// Streaming detector: per-set, window of last 3 address deltas (8 bits each)
struct StreamDetect {
    uint8_t delta[3]; // last 3 address deltas (block aligned)
    uint64_t last_addr;
    uint8_t ptr;
    uint8_t stream_score; // 2 bits: saturating counter
};
StreamDetect stream_state[LLC_SETS];

// Helper: assign leader sets deterministically
void InitLeaderSets() {
    leader_srrip.clear();
    leader_brrip.clear();
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i) {
        leader_srrip.push_back(i);
        leader_brrip.push_back(i + LLC_SETS/2);
    }
}

// Initialize replacement state
void InitReplacementState() {
    memset(meta, 0, sizeof(meta));
    memset(SHCT, 1, sizeof(SHCT)); // default weak reuse
    memset(stream_state, 0, sizeof(stream_state));
    InitLeaderSets();
    PSEL = 512;
}

// --- Helper: compress PC into 4 bits signature ---
inline uint8_t GetSignature(uint64_t PC) {
    return (PC ^ (PC >> 8) ^ (PC >> 16)) & 0xF;
}

// --- Helper: update streaming detector ---
void UpdateStreamDetector(uint32_t set, uint64_t paddr) {
    StreamDetect& sd = stream_state[set];
    uint64_t addr_blk = paddr >> 6; // block aligned
    if (sd.last_addr) {
        uint8_t delta = (uint8_t)(addr_blk - sd.last_addr);
        sd.delta[sd.ptr] = delta;
        sd.ptr = (sd.ptr + 1) % 3;

        // Detect monotonic stride pattern
        bool monotonic = true;
        for (int i = 1; i < 3; ++i)
            if (sd.delta[i] != sd.delta[0]) monotonic = false;

        if (monotonic && sd.delta[0] != 0)
            if (sd.stream_score < 3) sd.stream_score++;
        else
            if (sd.stream_score > 0) sd.stream_score--;
    }
    sd.last_addr = addr_blk;
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
    // Streaming bypass: if stream_score high, prefer invalid or RRPV==3, else bypass (return -1)
    if (stream_state[set].stream_score >= 3) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (!current_set[way].valid)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (meta[set][way].rrpv == 3)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (meta[set][way].rrpv < 3)
                meta[set][way].rrpv++;
        return 0;
    }

    // Regular RRIP victim selection
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
    // Update streaming detector
    UpdateStreamDetector(set, paddr);

    uint8_t sig = GetSignature(PC);

    // Update SHiP signature history table
    uint32_t shct_idx = ((set << 4) | sig) & (SHCT_SIZE-1);

    if (hit) {
        // If hit, promote block, increment SHCT
        meta[set][way].rrpv = 0;
        if (SHCT[shct_idx] < 3) SHCT[shct_idx]++;
        return;
    }

    // On fill: set SHiP signature
    meta[set][way].sig = sig;

    // Streaming phase: bypass if detector is strong
    if (stream_state[set].stream_score >= 3) {
        meta[set][way].rrpv = 3; // always distant; streaming blocks evicted quickly
        return;
    }

    // DIP set-dueling: check leader sets
    bool is_leader_srrip = false, is_leader_brrip = false;
    for (auto s : leader_srrip) if (set == s) is_leader_srrip = true;
    for (auto s : leader_brrip)  if (set == s) is_leader_brrip = true;

    // SHiP bias: if SHCT indicates strong reuse, insert at 0; else at 2 or 3
    uint8_t ins_rrpv = 2;
    if (SHCT[shct_idx] >= 2)
        ins_rrpv = 0;
    else
        ins_rrpv = 2;

    // Leader sets override insertion
    if (is_leader_srrip)
        ins_rrpv = 2; // SRRIP: always insert at 2
    else if (is_leader_brrip)
        ins_rrpv = (rand() % 32 == 0) ? 2 : 3; // BRRIP: mostly distant, rare at 2
    // Normal sets: pick policy based on PSEL
    else if (!is_leader_srrip && !is_leader_brrip) {
        if (PSEL >= 512)
            ins_rrpv = 2; // SRRIP
        else
            ins_rrpv = (rand() % 32 == 0) ? 2 : 3; // BRRIP
    }
    meta[set][way].rrpv = ins_rrpv;

    // DIP update for leader sets
    if (is_leader_srrip && hit && PSEL < 1023) PSEL++;
    if (is_leader_brrip && hit && PSEL > 0) PSEL--;

    // On eviction: if victim block did NOT get reused, penalize SHCT
    if (!hit) {
        uint8_t ev_sig = meta[set][way].sig;
        uint32_t ev_idx = ((set << 4) | ev_sig) & (SHCT_SIZE-1);
        if (SHCT[ev_idx] > 0) SHCT[ev_idx]--;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    uint32_t strong = 0, weak = 0;
    for (uint32_t i = 0; i < SHCT_SIZE; ++i)
        if (SHCT[i] >= 2) strong++; else weak++;
    std::cout << "SHiP-DSH: SHCT strong=" << strong << ", weak=" << weak << ", PSEL=" << PSEL << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // No additional statistics required
}