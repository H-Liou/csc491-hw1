#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

//---------------------------------------------
// DRRIP set-dueling: 64 leader sets, 10-bit PSEL
#define NUM_LEADER_SETS 64
#define PSEL_MAX 1023
uint16_t PSEL = PSEL_MAX/2; // 10-bit

uint8_t leader_set_type[NUM_LEADER_SETS]; // 0: SRRIP, 1: BRRIP
uint8_t set_type[LLC_SETS]; // 0: SRRIP, 1: BRRIP, 2: follower

//---------------------------------------------
// RRIP state: 2 bits per block
uint8_t rrpv[LLC_SETS][LLC_WAYS]; // 2 bits

//---------------------------------------------
// Streaming detector: 2 bits per set
uint8_t stream_ctr[LLC_SETS]; // 0–3
uint64_t last_addr[LLC_SETS];

//---------------------------------------------
// Mini-reuse counter: 2 bits per block
uint8_t reuse_ctr[LLC_SETS][LLC_WAYS]; // 0–3

//---------------------------------------------
// SHiP-Lite: 512-entry signature table, 2 bits per entry
#define SHIP_SIG_TABLE_SIZE 512
uint16_t ship_sig_table[SHIP_SIG_TABLE_SIZE]; // 2 bits per entry

//---------------------------------------------
// Helper: assign leader sets
void InitLeaderSets() {
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i)
        leader_set_type[i] = (i < NUM_LEADER_SETS/2) ? 0 : 1;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        set_type[set] = (set < NUM_LEADER_SETS) ? leader_set_type[set] : 2;
}

//---------------------------------------------
// Initialize replacement state
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv));    // distant
    memset(stream_ctr, 0, sizeof(stream_ctr));
    memset(last_addr, 0, sizeof(last_addr));
    memset(reuse_ctr, 0, sizeof(reuse_ctr));
    memset(ship_sig_table, 0, sizeof(ship_sig_table));
    InitLeaderSets();
    PSEL = PSEL_MAX/2;
}

//---------------------------------------------
// Find victim in the set (prefer dead block, then RRIP)
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Prefer invalid block
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (!current_set[way].valid)
            return way;
    // Prefer block with reuse_ctr == 0 (dead)
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (reuse_ctr[set][way] == 0)
            return way;
    // RRIP victim: RRPV==3
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] < 3)
                rrpv[set][way]++;
    }
}

//---------------------------------------------
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
    //--- Streaming detector update ---
    uint64_t addr_delta = (last_addr[set] > 0) ? (paddr - last_addr[set]) : 0;
    last_addr[set] = paddr;
    if (addr_delta == 64 || addr_delta == -64) {
        if (stream_ctr[set] < 3) stream_ctr[set]++;
    } else {
        if (stream_ctr[set] > 0) stream_ctr[set]--;
    }

    //--- SHiP-Lite signature extraction ---
    uint32_t sig_idx = (PC ^ set) & (SHIP_SIG_TABLE_SIZE-1);

    //--- Reuse counter update ---
    if (hit) {
        rrpv[set][way] = 0; // protect
        if (reuse_ctr[set][way] < 3) reuse_ctr[set][way]++;
        // SHiP-Lite: positive outcome
        if (ship_sig_table[sig_idx] < 3) ship_sig_table[sig_idx]++;
    } else {
        // On fill: streaming detected, bypass if strong
        if (stream_ctr[set] == 3) {
            // Streaming: bypass (insert at RRPV=3, mark as dead)
            rrpv[set][way] = 3;
            reuse_ctr[set][way] = 0;
            return;
        }

        // SHiP-Lite: use signature table to bias insertion
        uint8_t sig_val = ship_sig_table[sig_idx];

        // DRRIP insertion
        uint8_t ins_rrpv = 3; // default distant
        if (set_type[set] == 0) { // SRRIP: always insert at 2
            ins_rrpv = 2;
        } else if (set_type[set] == 1) { // BRRIP: insert at 3 most times, 1/32 at 2
            static uint32_t brrip_tick = 0;
            ins_rrpv = (brrip_tick++ % 32 == 0) ? 2 : 3;
        } else { // follower: use PSEL
            ins_rrpv = (PSEL >= PSEL_MAX/2) ? 2 : ((rand() % 32 == 0) ? 2 : 3);
        }

        // SHiP-Lite bias: if signature is hot, insert at 0/1
        if (sig_val >= 2) ins_rrpv = 1;
        if (sig_val == 3) ins_rrpv = 0;

        rrpv[set][way] = ins_rrpv;
        reuse_ctr[set][way] = (sig_val >= 2) ? 2 : 1;
    }

    //--- SHiP-Lite negative outcome (on eviction) ---
    if (!hit && victim_addr) {
        uint32_t victim_sig_idx = ((victim_addr >> 2) ^ set) & (SHIP_SIG_TABLE_SIZE-1);
        if (ship_sig_table[victim_sig_idx] > 0) ship_sig_table[victim_sig_idx]--;
    }

    //--- DRRIP set-dueling feedback ---
    // Only update PSEL for leader sets
    if (!hit) return; // Only update on hit
    if (set < NUM_LEADER_SETS) {
        if (leader_set_type[set] == 0) { // SRRIP leader
            if (PSEL < PSEL_MAX) PSEL++;
        } else if (leader_set_type[set] == 1) { // BRRIP leader
            if (PSEL > 0) PSEL--;
        }
    }
}

//---------------------------------------------
// Print end-of-simulation statistics
void PrintStats() {
    int protected_blocks = 0, distant_blocks = 0, dead_blocks = 0, streaming_sets = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (rrpv[set][way] == 0) protected_blocks++;
            if (rrpv[set][way] == 3) distant_blocks++;
            if (reuse_ctr[set][way] == 0) dead_blocks++;
        }
        if (stream_ctr[set] == 3) streaming_sets++;
    }
    int hot_sigs = 0;
    for (uint32_t i = 0; i < SHIP_SIG_TABLE_SIZE; ++i)
        if (ship_sig_table[i] >= 2) hot_sigs++;
    std::cout << "SHiP-Lite DRRIP + Streaming Bypass + Mini-Reuse Counter Policy" << std::endl;
    std::cout << "Protected blocks: " << protected_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "Distant blocks: " << distant_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "Dead blocks: " << dead_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "Streaming sets: " << streaming_sets << "/" << LLC_SETS << std::endl;
    std::cout << "Hot SHiP signatures: " << hot_sigs << "/" << SHIP_SIG_TABLE_SIZE << std::endl;
    std::cout << "PSEL: " << PSEL << "/" << PSEL_MAX << std::endl;
}

//---------------------------------------------
// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    int protected_blocks = 0, distant_blocks = 0, dead_blocks = 0, streaming_sets = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (rrpv[set][way] == 0) protected_blocks++;
            if (rrpv[set][way] == 3) distant_blocks++;
            if (reuse_ctr[set][way] == 0) dead_blocks++;
        }
        if (stream_ctr[set] == 3) streaming_sets++;
    }
    int hot_sigs = 0;
    for (uint32_t i = 0; i < SHIP_SIG_TABLE_SIZE; ++i)
        if (ship_sig_table[i] >= 2) hot_sigs++;
    std::cout << "Protected blocks (heartbeat): " << protected_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "Distant blocks (heartbeat): " << distant_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "Dead blocks (heartbeat): " << dead_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "Streaming sets (heartbeat): " << streaming_sets << "/" << LLC_SETS << std::endl;
    std::cout << "Hot SHiP signatures (heartbeat): " << hot_sigs << "/" << SHIP_SIG_TABLE_SIZE << std::endl;
    std::cout << "PSEL (heartbeat): " << PSEL << "/" << PSEL_MAX << std::endl;
}