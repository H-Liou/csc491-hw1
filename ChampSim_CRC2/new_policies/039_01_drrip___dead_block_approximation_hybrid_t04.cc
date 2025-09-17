#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// DRRIP parameters
#define RRPV_BITS 2
#define RRPV_MAX 3
#define PSEL_BITS 10
#define PSEL_MAX ((1 << PSEL_BITS) - 1)
#define NUM_LEADER_SETS 64

// Dead-block predictor: 2 bits per block
std::vector<uint8_t> block_rrpv;      // Per-block RRPV
std::vector<uint8_t> block_dead_cnt;  // Per-block dead-block counter

// DRRIP set-dueling state
std::vector<uint8_t> set_type;        // 0: SRRIP leader, 1: BRRIP leader, 2: follower
uint32_t psel = PSEL_MAX / 2;

// Stats
uint64_t access_counter = 0;
uint64_t hits = 0;
uint64_t sr_insert = 0;
uint64_t br_insert = 0;
uint64_t dead_insert = 0;

// Helper: assign leader sets for set-dueling
void assign_leader_sets() {
    set_type.resize(LLC_SETS, 2); // default: follower
    for (uint32_t i = 0; i < NUM_LEADER_SETS; i++) {
        set_type[i] = 0; // SRRIP leader
        set_type[LLC_SETS - 1 - i] = 1; // BRRIP leader
    }
}

// Initialization
void InitReplacementState() {
    block_rrpv.resize(LLC_SETS * LLC_WAYS, RRPV_MAX);
    block_dead_cnt.resize(LLC_SETS * LLC_WAYS, 1); // neutral: maybe live
    assign_leader_sets();
    access_counter = 0;
    hits = 0;
    sr_insert = 0;
    br_insert = 0;
    dead_insert = 0;
    psel = PSEL_MAX / 2;
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
    // Standard RRIP victim selection
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        size_t idx = set * LLC_WAYS + way;
        if (block_rrpv[idx] == RRPV_MAX)
            return way;
    }
    // Increment all RRPVs and retry
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        size_t idx = set * LLC_WAYS + way;
        if (block_rrpv[idx] < RRPV_MAX)
            block_rrpv[idx]++;
    }
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        size_t idx = set * LLC_WAYS + way;
        if (block_rrpv[idx] == RRPV_MAX)
            return way;
    }
    // Fallback
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
    access_counter++;
    size_t idx = set * LLC_WAYS + way;

    // --- Dead-block predictor update ---
    if (hit) {
        hits++;
        block_rrpv[idx] = 0; // promote to MRU
        if (block_dead_cnt[idx] < 3) block_dead_cnt[idx]++;
        return;
    }

    // Periodic decay: every 1024 accesses, decay all counters by 1
    if ((access_counter & 0x3FF) == 0) {
        for (auto& cnt : block_dead_cnt)
            if (cnt > 0) cnt--;
    }

    // --- DRRIP insertion depth selection ---
    uint8_t ins_rrpv = RRPV_MAX; // default distant

    bool is_leader_sr = (set_type[set] == 0);
    bool is_leader_br = (set_type[set] == 1);
    bool use_sr = (psel >= (PSEL_MAX / 2));

    // Dead-block: if predicted dead, always insert at RRPV=3
    if (block_dead_cnt[idx] == 0) {
        ins_rrpv = RRPV_MAX;
        dead_insert++;
    } else {
        // DRRIP: SRRIP inserts at RRPV=2, BRRIP inserts at RRPV=3 with low probability
        if (is_leader_sr || (set_type[set] == 2 && use_sr)) {
            ins_rrpv = RRPV_MAX - 1; // SRRIP: RRPV=2
            sr_insert++;
        } else {
            // BRRIP: RRPV=3 with 1/32 probability, else RRPV=2
            if ((access_counter & 0x1F) == 0) {
                ins_rrpv = RRPV_MAX;
            } else {
                ins_rrpv = RRPV_MAX - 1;
            }
            br_insert++;
        }
    }
    block_rrpv[idx] = ins_rrpv;

    // --- DRRIP set-dueling update ---
    // On miss in leader sets, update PSEL
    if (is_leader_sr && !hit) {
        if (psel < PSEL_MAX) psel++;
    } else if (is_leader_br && !hit) {
        if (psel > 0) psel--;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "DRRIP + Dead-Block Approximation Hybrid Policy\n";
    std::cout << "Total accesses: " << access_counter << "\n";
    std::cout << "Hits: " << hits << "\n";
    std::cout << "SRRIP inserts: " << sr_insert << "\n";
    std::cout << "BRRIP inserts: " << br_insert << "\n";
    std::cout << "Dead-block inserts: " << dead_insert << "\n";
    std::cout << "Final PSEL: " << psel << "\n";
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    std::cout << "DRRIP+Dead heartbeat: accesses=" << access_counter
              << ", hits=" << hits
              << ", SRRIP_inserts=" << sr_insert
              << ", BRRIP_inserts=" << br_insert
              << ", dead_inserts=" << dead_insert
              << ", PSEL=" << psel << "\n";
}