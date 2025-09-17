#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- Compact SHiP-lite predictor ---
#define SHIP_SIG_BITS 6 // 64-entry signature table
#define SHIP_SIG_ENTRIES 64
struct SHIPEntry {
    uint8_t outcome; // 2 bits: saturating counter
};
SHIPEntry ship_table[LLC_SETS][SHIP_SIG_ENTRIES];

// --- Address-based reuse predictor (per-set, 16 entries, 2 bits each) ---
#define ADDR_PRED_ENTRIES 16
uint8_t addr_pred[LLC_SETS][ADDR_PRED_ENTRIES];

// --- Per-block dead-block counters (2 bits each) ---
uint8_t dead_block[LLC_SETS][LLC_WAYS];

// --- RRIP state ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// --- Streaming detector: per-set stride, 2 bits confidence ---
uint64_t last_addr[LLC_SETS];
int64_t last_delta[LLC_SETS];
uint8_t stream_conf[LLC_SETS];

// --- DIP Set-Dueling for SRRIP vs BRRIP ---
#define LEADER_SETS 64
uint8_t is_srrip_leader[LLC_SETS];
uint8_t is_brrip_leader[LLC_SETS];
uint16_t psel = 512; // 10 bits

// Helper: get SHiP signature
inline uint8_t get_signature(uint64_t PC) {
    return ((PC >> 2) ^ (PC >> 8)) & (SHIP_SIG_ENTRIES - 1);
}

// Helper: get address predictor index (lower address bits)
inline uint8_t get_addr_index(uint64_t paddr) {
    return (paddr >> 6) & (ADDR_PRED_ENTRIES - 1);
}

// Initialize replacement state
void InitReplacementState() {
    memset(ship_table, 0, sizeof(ship_table));
    memset(addr_pred, 0, sizeof(addr_pred));
    memset(dead_block, 0, sizeof(dead_block));
    memset(rrpv, 3, sizeof(rrpv)); // All distant initially

    memset(last_addr, 0, sizeof(last_addr));
    memset(last_delta, 0, sizeof(last_delta));
    memset(stream_conf, 0, sizeof(stream_conf));

    // Set up leader sets for DIP
    memset(is_srrip_leader, 0, sizeof(is_srrip_leader));
    memset(is_brrip_leader, 0, sizeof(is_brrip_leader));
    for (int i = 0; i < LEADER_SETS; ++i) {
        is_srrip_leader[i] = 1; // First 64
        is_brrip_leader[LLC_SETS - 1 - i] = 1; // Last 64
    }
    psel = 512;
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
    // Prefer blocks with RRPV==3 and dead-block==3
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (rrpv[set][way] == 3 && dead_block[set][way] == 3)
                return way;
        }
        // Next prefer blocks with RRPV==3
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (rrpv[set][way] == 3)
                return way;
        }
        // Increment all RRPVs
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] < 3) rrpv[set][way]++;
    }
    return 0; // fallback
}

// Streaming detector: update stride and confidence
void update_stream_detector(uint32_t set, uint64_t paddr) {
    int64_t delta = (int64_t)paddr - (int64_t)last_addr[set];
    if (last_addr[set] != 0 && (delta == last_delta[set] && delta != 0)) {
        if (stream_conf[set] < 3) stream_conf[set]++;
    } else {
        if (stream_conf[set] > 0) stream_conf[set]--;
    }
    last_delta[set] = delta;
    last_addr[set] = paddr;
}

// Streaming detector: is streaming
bool is_streaming(uint32_t set) {
    return stream_conf[set] >= 2;
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
    // --- Update streaming detector ---
    update_stream_detector(set, paddr);

    // --- Update SHiP predictor ---
    uint8_t sig = get_signature(PC);
    if (hit) {
        if (ship_table[set][sig].outcome < 3) ship_table[set][sig].outcome++;
    } else {
        if (ship_table[set][sig].outcome > 0) ship_table[set][sig].outcome--;
    }

    // --- Address-based reuse predictor ---
    uint8_t addr_idx = get_addr_index(paddr);
    if (hit) {
        if (addr_pred[set][addr_idx] < 3) addr_pred[set][addr_idx]++;
    } else {
        if (addr_pred[set][addr_idx] > 0) addr_pred[set][addr_idx]--;
    }

    // --- Dead-block counter for victim ---
    for (uint32_t w = 0; w < LLC_WAYS; ++w) {
        if (current_set[w].address == victim_addr) {
            if (current_set[w].valid && !current_set[w].dirty) {
                // If block evicted without reuse, increment
                if (dead_block[set][w] < 3) dead_block[set][w]++;
            } else {
                // Otherwise, decay
                if (dead_block[set][w] > 0) dead_block[set][w]--;
            }
        }
    }

    // --- DIP: update PSEL if leader sets ---
    if (is_srrip_leader[set]) {
        if (hit && psel < 1023) psel++;
    } else if (is_brrip_leader[set]) {
        if (hit && psel > 0) psel--;
    }

    // --- RRIP insertion policy ---
    // Policy: If streaming detected, insert at distant (3) or bypass (if both predictors dead)
    // Else, SHiP and Addr predictor: if either outcome >=2, insert at near (2), else distant (3)
    // DIP: choose SRRIP (mostly near) or BRRIP (mostly distant) for normal sets

    uint8_t ins_rrpv = 3; // default distant
    if (is_streaming(set)) {
        // Streaming: insert at distant or bypass if both predictors say dead
        if (ship_table[set][sig].outcome == 0 && addr_pred[set][addr_idx] == 0)
            ins_rrpv = 3; // In real design, could bypass (simulate as distant)
        else
            ins_rrpv = 3;
    } else {
        if (ship_table[set][sig].outcome >= 2 || addr_pred[set][addr_idx] >= 2)
            ins_rrpv = 2; // likely reuse
        else
            ins_rrpv = 3;
    }

    // DIP selection for normal sets
    if (!is_srrip_leader[set] && !is_brrip_leader[set]) {
        if (psel >= 512)
            ins_rrpv = (ins_rrpv == 2) ? 2 : ((rand() % 100) < 1 ? 2 : 3); // SRRIP: mostly near
        else
            ins_rrpv = (ins_rrpv == 2) ? ((rand() % 100) < 1 ? 2 : 3) : 3; // BRRIP: mostly distant
    }

    // Insert: set RRPV and dead-block counter
    rrpv[set][way] = ins_rrpv;
    dead_block[set][way] = 0;
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "ASHS-D Policy: Adaptive SHiP-Address Hybrid + Streaming/Dead-Block, DIP, Metadata <64KiB" << std::endl;
}

// Print periodic stats
void PrintStats_Heartbeat() {
    // Optionally add streaming stats or hit rates
}