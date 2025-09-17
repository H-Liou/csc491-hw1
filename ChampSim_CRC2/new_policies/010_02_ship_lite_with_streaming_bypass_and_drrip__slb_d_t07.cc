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

// SHiP-lite: 6-bit PC signature per block
uint8_t pc_sig[LLC_SETS][LLC_WAYS];      // 6 bits/block

// SHiP-lite: 64-entry outcome table (indexed by signature), 2 bits/entry
uint8_t ship_table[64]; // 2 bits per entry

// DRRIP: 10-bit PSEL
uint16_t PSEL = 512; // 10 bits, mid-value

// DRRIP: 32 leader sets (16 SRRIP, 16 BRRIP)
const uint32_t NUM_LEADER_SETS = 32;
const uint32_t LEADER_SETS_SRRIP = 16;
const uint32_t LEADER_SETS_BRRIP = 16;
bool is_leader_set_srrip[LLC_SETS];
bool is_leader_set_brrip[LLC_SETS];

// Streaming detector: per-set, track last address and delta, 3b monotonic counter
uint64_t last_addr[LLC_SETS];
int64_t last_delta[LLC_SETS];
uint8_t stream_counter[LLC_SETS]; // 0-7, saturate

const uint8_t STREAM_THRESHOLD = 6; // If monotonicity >=6, treat as streaming

// Helper: hash PC to 6 bits
inline uint8_t pc_hash(uint64_t PC) {
    return (PC ^ (PC >> 6) ^ (PC >> 12)) & 0x3F;
}

// Assign leader sets for DRRIP
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
    memset(rrpv, 3, sizeof(rrpv));
    memset(pc_sig, 0, sizeof(pc_sig));
    memset(ship_table, 1, sizeof(ship_table)); // weakly reused
    memset(last_addr, 0, sizeof(last_addr));
    memset(last_delta, 0, sizeof(last_delta));
    memset(stream_counter, 0, sizeof(stream_counter));
    PSEL = 512; // midpoint
    AssignLeaderSets();
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
    // Streaming detector: If streaming, suggest bypass (return invalid index)
    if (stream_counter[set] >= STREAM_THRESHOLD) {
        return LLC_WAYS; // bypass signal
    }
    // Otherwise, standard RRIP: prefer block with RRPV==3
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] < 3)
                rrpv[set][way]++;
    }
    return 0;
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
    int64_t delta = int64_t(paddr) - int64_t(last_addr[set]);
    if (last_addr[set] != 0) {
        if (delta == last_delta[set] && delta != 0) {
            if (stream_counter[set] < 7) stream_counter[set]++;
        } else {
            if (stream_counter[set] > 0) stream_counter[set]--;
        }
    }
    last_addr[set] = paddr;
    last_delta[set] = delta;

    // --- SHiP-lite signature ---
    uint8_t sig = pc_hash(PC);

    // --- DRRIP insertion policy selection ---
    bool use_srrip = false, use_brrip = false;
    if (is_leader_set_srrip[set]) use_srrip = true;
    else if (is_leader_set_brrip[set]) use_brrip = true;
    else use_srrip = (PSEL >= 512);

    // --- On cache hit ---
    if (hit) {
        rrpv[set][way] = 0; // MRU
        // Update SHiP outcome: increment reuse
        if (ship_table[pc_sig[set][way]] < 3) ship_table[pc_sig[set][way]]++;
        // DRRIP: On hit in leader sets, increment PSEL for SRRIP, decrement for BRRIP
        if (is_leader_set_srrip[set] && PSEL < 1023) PSEL++;
        if (is_leader_set_brrip[set] && PSEL > 0) PSEL--;
        return;
    }

    // --- On cache miss or fill ---
    // Streaming detector: bypass block if streaming detected
    if (stream_counter[set] >= STREAM_THRESHOLD) {
        // Do not insert into LLC (simulate bypass)
        return;
    }

    // Choose insertion RRPV
    uint8_t ins_rrpv;
    if (use_srrip) {
        ins_rrpv = 2; // SRRIP: insert at distant-RRPV
    } else if (use_brrip) {
        // BRRIP: insert at RRPV=2, but occasionally at MRU (RRPV=0, every 1/32 fills)
        static uint32_t brrip_counter = 0;
        if ((brrip_counter++ % 32) == 0)
            ins_rrpv = 0;
        else
            ins_rrpv = 2;
    } else {
        // Dynamic: use PSEL winner
        ins_rrpv = (PSEL >= 512) ? 2 : 2;
    }

    // SHiP bias: if PC signature is frequently reused, insert at MRU
    if (ship_table[sig] >= 2)
        ins_rrpv = 0;

    // Update block metadata
    pc_sig[set][way] = sig;
    rrpv[set][way] = ins_rrpv;
    // SHiP outcome: weak initial prediction
    if (ship_table[sig] > 0) ship_table[sig]--;

    // DRRIP: On miss in leader sets, decrement PSEL for SRRIP, increment for BRRIP
    if (is_leader_set_srrip[set] && PSEL > 0) PSEL--;
    if (is_leader_set_brrip[set] && PSEL < 1023) PSEL++;
}

// Print end-of-simulation statistics
void PrintStats() {
    // Streaming summary
    uint64_t streaming_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (stream_counter[s] >= STREAM_THRESHOLD)
            streaming_sets++;
    std::cout << "SLB-D: streaming sets at end: " << streaming_sets << " / " << LLC_SETS << std::endl;

    // SHiP table summary
    std::cout << "SLB-D: SHiP table (reuse counters): ";
    for (int i = 0; i < 64; ++i)
        std::cout << (int)ship_table[i] << " ";
    std::cout << std::endl;

    // Print PSEL value
    std::cout << "SLB-D: DRRIP PSEL = " << (int)PSEL << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Optionally print streaming ratio or PSEL
}