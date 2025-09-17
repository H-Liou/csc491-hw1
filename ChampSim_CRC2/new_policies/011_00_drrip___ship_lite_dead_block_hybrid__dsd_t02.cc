#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- DRRIP metadata ---
static uint8_t rrpv[LLC_SETS][LLC_WAYS];         // 2 bits per line
static uint8_t leader_set_type[LLC_SETS];        // 0: SRRIP, 1: BRRIP, 2: follower
static uint16_t PSEL = 512;                      // 10-bit policy selector

// --- SHiP-Lite metadata ---
static uint8_t sig[LLC_SETS][LLC_WAYS];          // 5 bits per line (PC signature)
static uint8_t outcome[LLC_SETS][LLC_WAYS];      // 2 bits per line (reuse counter)
static uint8_t sig_table[32];                    // 2 bits per signature

// --- Dead-block predictor ---
static uint8_t dead[LLC_SETS][LLC_WAYS];         // 1 bit per line

// --- Leader set allocation ---
static std::vector<uint32_t> sr_leader_sets;
static std::vector<uint32_t> br_leader_sets;

void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv));      // All lines: RRPV=3 (long re-use distance)
    memset(sig, 0, sizeof(sig));
    memset(outcome, 0, sizeof(outcome));
    memset(sig_table, 1, sizeof(sig_table)); // Default: weakly reused
    memset(dead, 0, sizeof(dead));
    memset(leader_set_type, 2, sizeof(leader_set_type)); // 2: follower

    // Allocate 32 leader sets for SRRIP, 32 for BRRIP
    sr_leader_sets.clear();
    br_leader_sets.clear();
    for (uint32_t i = 0; i < 32; ++i) {
        sr_leader_sets.push_back(i);
        br_leader_sets.push_back(LLC_SETS - 1 - i);
        leader_set_type[i] = 0; // SRRIP leader
        leader_set_type[LLC_SETS - 1 - i] = 1; // BRRIP leader
    }
    PSEL = 512; // Middle value for 10-bit counter
}

// --- Compute 5-bit PC signature ---
inline uint8_t GetSignature(uint64_t PC) {
    // Simple hash: lower 5 bits XOR upper 5 bits
    return ((PC >> 2) ^ (PC >> 13)) & 0x1F;
}

// --- Victim selection (SRRIP method) ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] < 3) ++rrpv[set][way];
    }
    return 0;
}

// --- Update replacement state ---
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
    uint8_t signature = GetSignature(PC);

    // --- On hit: promote to MRU, update outcome ---
    if (hit) {
        rrpv[set][way] = 0;
        if (outcome[set][way] < 3) outcome[set][way]++;
        if (sig_table[sig[set][way]] < 3) sig_table[sig[set][way]]++;
        dead[set][way] = 0; // Not dead
        return;
    }

    // --- On eviction: update outcome table and dead-block predictor ---
    if (outcome[set][way] == 0) {
        // Block never reused: decrement signature outcome, mark dead
        if (sig_table[sig[set][way]] > 0) sig_table[sig[set][way]]--;
        dead[set][way] = 1;
    } else {
        dead[set][way] = 0;
    }
    outcome[set][way] = 0;

    // --- DRRIP set-dueling: choose insertion depth ---
    uint8_t ins_rrpv = 2; // Default SRRIP insertion

    if (leader_set_type[set] == 0) { // SRRIP leader
        ins_rrpv = 2;
    } else if (leader_set_type[set] == 1) { // BRRIP leader
        ins_rrpv = (rand() % 32 == 0) ? 2 : 3; // 1/32 probability for RRPV=2, else 3
    } else { // Follower
        ins_rrpv = (PSEL >= 512) ? 2 : ((rand() % 32 == 0) ? 2 : 3);
    }

    // --- SHiP-Lite bias: if signature is frequently reused, insert at MRU ---
    if (sig_table[signature] >= 2) {
        ins_rrpv = 0;
    } else if (sig_table[signature] == 1) {
        ins_rrpv = std::max(ins_rrpv, (uint8_t)2);
    }

    // --- Dead-block bias: if last block was dead, penalize insertion depth ---
    if (dead[set][way]) {
        ins_rrpv = 3;
    }

    rrpv[set][way] = ins_rrpv;
    sig[set][way] = signature;

    // --- DRRIP set-dueling: update PSEL ---
    if (leader_set_type[set] == 0) { // SRRIP leader
        if (hit && PSEL < 1023) PSEL++;
    } else if (leader_set_type[set] == 1) { // BRRIP leader
        if (hit && PSEL > 0) PSEL--;
    }
}

// --- Print statistics ---
void PrintStats() {
    std::cout << "DSD Policy: DRRIP + SHiP-Lite Dead-Block Hybrid\n";
    std::cout << "PSEL: " << PSEL << std::endl;
    // Print signature outcome histogram
    uint32_t sig_hist[4] = {0,0,0,0};
    for (int i=0; i<32; ++i) sig_hist[sig_table[i]]++;
    std::cout << "Signature outcome histogram: ";
    for (int i=0; i<4; ++i) std::cout << sig_hist[i] << " ";
    std::cout << std::endl;
    // Dead-block histogram
    uint32_t dead_count = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            dead_count += dead[set][way];
    std::cout << "Dead blocks flagged: " << dead_count << std::endl;
}

void PrintStats_Heartbeat() {}