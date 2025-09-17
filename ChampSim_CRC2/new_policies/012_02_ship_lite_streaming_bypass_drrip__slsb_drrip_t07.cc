#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// RRIP metadata: 2 bits/block
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// SHiP-lite: per-line 5-bit PC sig, global table 32 x 2 bits
uint8_t pc_sig[LLC_SETS][LLC_WAYS]; // 5 bits/block
uint8_t pc_table[32];               // 2 bits/entry

// Streaming detector: per-set last addr/delta, 3-bit confidence, 1-bit streaming flag
uint64_t last_addr[LLC_SETS];
int64_t last_delta[LLC_SETS];
uint8_t stream_conf[LLC_SETS];      // 3 bits/set
uint8_t streaming_flag[LLC_SETS];   // 1 bit/set

// DRRIP set-dueling: 64 leader sets (32 SRRIP, 32 BRRIP), 10-bit PSEL
const uint32_t NUM_LEADER_SETS = 64;
const uint32_t LEADER_SETS_SRRIP = 32;
const uint32_t LEADER_SETS_BRRIP = 32;
bool is_leader_set_srrip[LLC_SETS];
bool is_leader_set_brrip[LLC_SETS];
uint16_t PSEL = 512; // 10 bits, mid-value

// Helper: hash PC to 5 bits (0..31)
inline uint8_t pc_hash(uint64_t PC) {
    // CRC32 bits folded to 5 bits
    return (champsim_crc2(PC, 0x1234) ^ (PC>>11) ^ (PC>>17)) & 0x1F;
}

// Assign leader sets for DRRIP set-dueling
void AssignLeaderSets() {
    memset(is_leader_set_srrip, 0, sizeof(is_leader_set_srrip));
    memset(is_leader_set_brrip, 0, sizeof(is_leader_set_brrip));
    for (uint32_t i = 0; i < LEADER_SETS_SRRIP; ++i)
        is_leader_set_srrip[(i * LLC_SETS) / NUM_LEADER_SETS] = true;
    for (uint32_t i = 0; i < LEADER_SETS_BRRIP; ++i)
        is_leader_set_brrip[(i * LLC_SETS) / NUM_LEADER_SETS + 1] = true;
}

// Initialize replacement state
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv)); // fill with distant RRPV
    memset(pc_sig, 0, sizeof(pc_sig));
    memset(pc_table, 1, sizeof(pc_table)); // weak reuse
    PSEL = 512;
    AssignLeaderSets();
    memset(last_addr, 0, sizeof(last_addr));
    memset(last_delta, 0, sizeof(last_delta));
    memset(stream_conf, 0, sizeof(stream_conf));
    memset(streaming_flag, 0, sizeof(streaming_flag));
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
    // Streaming: prefer to bypass on fill if streaming_flag is set
    // If bypass, caller should not fill the cache at all; but here, we must select a victim if a fill occurs
    // So, prefer block with RRPV==3
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (rrpv[set][way] == 3)
            return way;
    // Increment RRPV until found
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] < 3)
                rrpv[set][way]++;
    }
    return 0; // Shouldn't reach
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
    int64_t delta = (last_addr[set] != 0) ? ((int64_t)paddr - (int64_t)last_addr[set]) : 0;
    if (last_addr[set] != 0 && delta == last_delta[set]) {
        if (stream_conf[set] < 7) stream_conf[set]++;
    } else {
        if (stream_conf[set] > 0) stream_conf[set]--;
    }
    last_addr[set] = paddr;
    last_delta[set] = delta;
    streaming_flag[set] = (stream_conf[set] >= 5) ? 1 : 0;

    // --- SHiP-lite: PC signature ---
    uint8_t sig = pc_hash(PC);

    // --- DRRIP set-dueling: choose SRRIP or BRRIP ---
    bool use_srrip = false, use_brrip = false;
    if (is_leader_set_srrip[set]) use_srrip = true;
    else if (is_leader_set_brrip[set]) use_brrip = true;
    else use_srrip = (PSEL >= 512);

    // --- Streaming bypass logic ---
    if (!hit && streaming_flag[set]) {
        // Bypass: do not fill the block at all
        // But if required to fill (e.g., for correctness), use RRPV=3
        rrpv[set][way] = 3;
        pc_sig[set][way] = sig; // still update signature
        // Decay PC table
        if (pc_table[sig] > 0) pc_table[sig]--;
        // DRRIP set-dueling PSEL update: treat as miss in BRRIP/SRRIP leader sets
        if (is_leader_set_srrip[set] && PSEL > 0) PSEL--;
        if (is_leader_set_brrip[set] && PSEL < 1023) PSEL++;
        return;
    }

    // --- On cache hit ---
    if (hit) {
        rrpv[set][way] = 0; // MRU
        // PC outcome counter increases
        if (pc_table[pc_sig[set][way]] < 3) pc_table[pc_sig[set][way]]++;
        // DRRIP set-dueling PSEL update: hit in leader sets
        if (is_leader_set_srrip[set] && PSEL < 1023) PSEL++;
        if (is_leader_set_brrip[set] && PSEL > 0) PSEL--;
        return;
    }

    // --- On miss/fill ---
    uint8_t ins_rrpv;
    if (use_srrip)
        ins_rrpv = 2; // SRRIP default
    else if (use_brrip) {
        // BRRIP: insert at RRPV=3 one out of 32 fills
        static uint32_t br_counter = 0;
        ins_rrpv = ((br_counter++ % 32) == 0) ? 3 : 2;
    } else {
        ins_rrpv = (PSEL >= 512) ? 2 : 3;
    }

    // SHiP-lite: if PC shows high reuse, insert at MRU
    if (pc_table[sig] >= 2)
        ins_rrpv = 0;

    // Streaming: if streaming detected AND not bypassing, insert at LRU (RRIP=3)
    if (streaming_flag[set])
        ins_rrpv = 3;

    // Fill block metadata
    pc_sig[set][way] = sig;
    rrpv[set][way] = ins_rrpv;
    // Decay PC table for new fills (if not hit)
    if (pc_table[sig] > 0) pc_table[sig]--;

    // DRRIP set-dueling PSEL update: miss in leader sets
    if (is_leader_set_srrip[set] && PSEL > 0) PSEL--;
    if (is_leader_set_brrip[set] && PSEL < 1023) PSEL++;
}

// Print end-of-simulation statistics
void PrintStats() {
    // Streaming summary
    uint64_t streaming_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (streaming_flag[s]) streaming_sets++;
    std::cout << "SLSB-DRRIP: Streaming sets at end: " << streaming_sets << " / " << LLC_SETS << std::endl;

    // PC table summary
    std::cout << "SLSB-DRRIP: PC table (reuse counters): ";
    for (int i = 0; i < 32; ++i)
        std::cout << (int)pc_table[i] << " ";
    std::cout << std::endl;

    // Print PSEL value
    std::cout << "SLSB-DRRIP: DRRIP PSEL = " << (int)PSEL << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // No periodic decay needed (SHiP-lite does implicit decay)
}