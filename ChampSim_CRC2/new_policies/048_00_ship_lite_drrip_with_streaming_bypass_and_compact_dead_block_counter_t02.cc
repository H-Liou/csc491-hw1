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
// Dead-block counter: 2 bits per block
uint8_t dead_ctr[LLC_SETS][LLC_WAYS]; // 0–3

//---------------------------------------------
// Streaming detector: 2 bits per set
uint8_t stream_ctr[LLC_SETS]; // 0–3
uint64_t last_addr[LLC_SETS];

//---------------------------------------------
// SHiP-lite: 6-bit PC signature, 2-bit outcome counter, 256 entries
#define SHIP_SIG_BITS 6
#define SHIP_TABLE_SIZE (1 << SHIP_SIG_BITS)
uint8_t ship_table[SHIP_TABLE_SIZE]; // 2 bits per entry

// Per-block signature
uint8_t block_sig[LLC_SETS][LLC_WAYS]; // 6 bits per block

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
    memset(dead_ctr, 0, sizeof(dead_ctr));
    memset(stream_ctr, 0, sizeof(stream_ctr));
    memset(last_addr, 0, sizeof(last_addr));
    memset(ship_table, 1, sizeof(ship_table)); // neutral
    memset(block_sig, 0, sizeof(block_sig));
    InitLeaderSets();
    PSEL = PSEL_MAX/2;
}

//---------------------------------------------
// Find victim in the set (dead-block counter first, then RRIP)
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
    // Dead-block counter: prefer blocks with counter==3
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (dead_ctr[set][way] == 3)
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

    //--- SHiP-lite signature extraction ---
    uint8_t sig = (PC >> 2) & (SHIP_TABLE_SIZE - 1);

    //--- Dead-block counter update ---
    if (hit) {
        rrpv[set][way] = 0; // protect
        dead_ctr[set][way] = 0; // reused: reset dead counter
        // SHiP: increment outcome counter (max 3)
        if (ship_table[block_sig[set][way]] < 3)
            ship_table[block_sig[set][way]]++;
    } else {
        // On fill: streaming detected, bypass if strong
        if (stream_ctr[set] == 3) {
            // Streaming: bypass (mark block as dead, insert at RRPV=3)
            rrpv[set][way] = 3;
            dead_ctr[set][way] = 3;
            block_sig[set][way] = sig;
            return;
        }

        // SHiP-lite insertion
        uint8_t ins_rrpv = 3; // default distant
        if (ship_table[sig] >= 2) {
            ins_rrpv = 0; // protect if signature shows reuse
        } else if (set_type[set] == 0) { // SRRIP leader
            ins_rrpv = 2;
        } else if (set_type[set] == 1) { // BRRIP leader
            static uint32_t brrip_tick = 0;
            ins_rrpv = (brrip_tick++ % 32 == 0) ? 2 : 3;
        } else { // follower: use PSEL
            ins_rrpv = (PSEL >= PSEL_MAX/2) ? 2 : ((rand() % 32 == 0) ? 2 : 3);
        }
        rrpv[set][way] = ins_rrpv;
        dead_ctr[set][way] = 0; // filled: assume live
        block_sig[set][way] = sig;
    }

    //--- DRRIP set-dueling feedback ---
    // Only update PSEL for leader sets, on hit
    if (hit && set < NUM_LEADER_SETS) {
        if (leader_set_type[set] == 0) { // SRRIP leader
            if (PSEL < PSEL_MAX) PSEL++;
        } else if (leader_set_type[set] == 1) { // BRRIP leader
            if (PSEL > 0) PSEL--;
        }
    }

    //--- Dead-block counter periodic decay ---
    static uint64_t global_tick = 0;
    global_tick++;
    if ((global_tick & 0xFFF) == 0) { // every 4096 updates
        for (uint32_t w = 0; w < LLC_WAYS; ++w)
            if (dead_ctr[set][w] < 3)
                dead_ctr[set][w]++;
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
            if (dead_ctr[set][way] == 3) dead_blocks++;
        }
        if (stream_ctr[set] == 3) streaming_sets++;
    }
    std::cout << "SHiP-Lite DRRIP + Streaming Bypass + Dead-Block Counter Policy" << std::endl;
    std::cout << "Protected blocks: " << protected_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "Distant blocks: " << distant_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "Dead blocks (ctr==3): " << dead_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "Streaming sets: " << streaming_sets << "/" << LLC_SETS << std::endl;
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
            if (dead_ctr[set][way] == 3) dead_blocks++;
        }
        if (stream_ctr[set] == 3) streaming_sets++;
    }
    std::cout << "Protected blocks (heartbeat): " << protected_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "Distant blocks (heartbeat): " << distant_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "Dead blocks (ctr==3, heartbeat): " << dead_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "Streaming sets (heartbeat): " << streaming_sets << "/" << LLC_SETS << std::endl;
    std::cout << "PSEL (heartbeat): " << PSEL << "/" << PSEL_MAX << std::endl;
}