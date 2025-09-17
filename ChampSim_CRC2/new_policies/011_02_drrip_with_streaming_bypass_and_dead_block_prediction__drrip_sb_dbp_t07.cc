#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- RRIP metadata ---
uint8_t rrpv[LLC_SETS][LLC_WAYS]; // 2 bits/line

// --- Dead-block predictor: per-line 2-bit counter ---
uint8_t dbp[LLC_SETS][LLC_WAYS]; // 2 bits/line: 0=live, 1-2=likely dead

// --- Streaming detector: per-set 1-bit flag, 32-bit last address ---
uint8_t streaming_flag[LLC_SETS];
uint32_t last_addr[LLC_SETS];

// --- DRRIP set-dueling: 10-bit PSEL, 64 leader sets ---
#define NUM_LEADER_SETS 64
uint16_t psel = 512; // 10 bits, range [0,1023]
bool leader_set[LLC_SETS];

// --- Leader set initialization ---
void InitLeaderSets() {
    memset(leader_set, 0, sizeof(leader_set));
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i) {
        leader_set[i] = true; // First 64 sets are leaders for SRRIP
        leader_set[LLC_SETS - 1 - i] = true; // Last 64 sets are leaders for BRRIP
    }
}

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv)); // Initialize to LRU (RRPV=3)
    memset(dbp, 0, sizeof(dbp));
    memset(streaming_flag, 0, sizeof(streaming_flag));
    memset(last_addr, 0, sizeof(last_addr));
    InitLeaderSets();
    psel = 512;
}

// --- Victim selection: standard RRIP ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Streaming phase: bypass insertion, always evict LRU if needed
    if (streaming_flag[set]) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            rrpv[set][way]++;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
    }

    // Dead-block first: prefer evicting blocks predicted dead (dbp>=2)
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (dbp[set][way] >= 2 && rrpv[set][way] == 3)
            return way;

    // Normal RRIP victim selection
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] < 3)
                rrpv[set][way]++;
    }
}

// --- Replacement state update ---
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
    uint32_t block_addr = (uint32_t)(paddr >> 6); // block address
    uint32_t last = last_addr[set];
    uint32_t delta = block_addr - last;
    if (last != 0) {
        if (delta == 1 || delta == (uint32_t)-1)
            streaming_flag[set] = 1;
        else if (delta != 0)
            streaming_flag[set] = 0;
    }
    last_addr[set] = block_addr;

    // --- Dead-block predictor update ---
    if (hit) {
        dbp[set][way] = 0; // Mark as live on hit
    } else {
        if (dbp[set][way] < 2)
            dbp[set][way]++; // Increase deadness on miss
    }

    // --- Periodic decay (simple aging) ---
    static uint64_t access_ctr = 0;
    if (++access_ctr % (LLC_SETS * LLC_WAYS) == 0) {
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            for (uint32_t w = 0; w < LLC_WAYS; ++w)
                if (dbp[s][w] > 0)
                    dbp[s][w]--; // Decay deadness, allow for phase change
    }

    // --- DRRIP insertion policy ---
    bool is_leader = leader_set[set];
    bool use_brrip = false;

    // Leader set selection:
    if (is_leader) {
        if (set < NUM_LEADER_SETS)
            use_brrip = false; // SRRIP leader
        else if (set >= LLC_SETS - NUM_LEADER_SETS)
            use_brrip = true; // BRRIP leader
    } else {
        use_brrip = (psel >= 512);
    }

    // --- Streaming bypass: do not insert block (simulate by setting RRPV to 3) ---
    uint8_t ins_rrpv = 2; // Default SRRIP insertion (long)
    if (streaming_flag[set]) {
        ins_rrpv = 3; // LRU (or bypass if possible)
    } else if (dbp[set][way] >= 2) {
        ins_rrpv = 3; // Insert predicted dead at LRU
    } else if (use_brrip) {
        ins_rrpv = (rand() % 32 == 0) ? 2 : 3; // BRRIP: insert at MRU with 1/32 probability
    } else {
        ins_rrpv = 2; // SRRIP default
    }

    // --- RRIP update ---
    if (hit)
        rrpv[set][way] = 0;
    else
        rrpv[set][way] = ins_rrpv;

    // --- PSEL update for leader sets ---
    if (is_leader && !streaming_flag[set]) {
        if (set < NUM_LEADER_SETS) {
            // SRRIP leader: increment PSEL on hit
            if (hit && psel < 1023) psel++;
            else if (!hit && psel > 0) psel--;
        } else if (set >= LLC_SETS - NUM_LEADER_SETS) {
            // BRRIP leader: decrement PSEL on hit
            if (hit && psel > 0) psel--;
            else if (!hit && psel < 1023) psel++;
        }
    }
}

// --- Stats ---
void PrintStats() {
    int streaming_sets = 0, dead_lines = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s) {
        if (streaming_flag[s]) streaming_sets++;
        for (uint32_t w = 0; w < LLC_WAYS; ++w)
            if (dbp[s][w] >= 2) dead_lines++;
    }
    std::cout << "DRRIP-SB-DBP: Streaming sets: " << streaming_sets << " / " << LLC_SETS << std::endl;
    std::cout << "DRRIP-SB-DBP: Dead lines: " << dead_lines << " / " << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "DRRIP-SB-DBP: PSEL: " << psel << std::endl;
}

void PrintStats_Heartbeat() {
    int streaming_sets = 0, dead_lines = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s) {
        if (streaming_flag[s]) streaming_sets++;
        for (uint32_t w = 0; w < LLC_WAYS; ++w)
            if (dbp[s][w] >= 2) dead_lines++;
    }
    std::cout << "DRRIP-SB-DBP: Streaming sets: " << streaming_sets << ", Dead lines: " << dead_lines << ", PSEL: " << psel << std::endl;
}