#include <vector>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// ---- SHiP-lite Metadata ----
#define SIG_BITS 6
#define OUTCOME_BITS 2
uint8_t block_sig[LLC_SETS][LLC_WAYS];      // 6 bits per block: PC signature
uint8_t block_outcome[LLC_SETS][LLC_WAYS];  // 2 bits per block: reuse counter

// ---- RRIP Metadata ----
uint8_t rrpv[LLC_SETS][LLC_WAYS]; // 2 bits per block

// ---- Streaming Detector ----
uint16_t last_addr[LLC_SETS];         // Last address seen per set (lower 16 bits)
uint8_t stream_ctr[LLC_SETS];         // 2 bits per set: streaming confidence

// ---- SHiP outcome table ----
#define SHIP_TABLE_SIZE 1024
struct SHIPEntry {
    uint8_t outcome; // 2 bits
};
SHIPEntry ship_table[SHIP_TABLE_SIZE];

// ---- Set-dueling for SHiP vs RRIP ----
#define NUM_LEADER_SETS 64
#define PSEL_BITS 10
uint16_t PSEL = 512; // 10-bit selector, starts neutral
uint8_t leader_set_type[NUM_LEADER_SETS]; // 0: SHiP, 1: RRIP

std::vector<uint32_t> leader_sets;

// Helper: hash PC to signature
inline uint8_t GetSignature(uint64_t PC) {
    return (PC ^ (PC >> 6) ^ (PC >> 12)) & ((1 << SIG_BITS) - 1);
}

// Helper: hash signature to SHIP table index
inline uint32_t SHIPIndex(uint8_t sig) {
    return sig;
}

// Helper: is this set a leader set? Returns 0=SHiP, 1=RRIP, 2=Follower
uint8_t GetSetType(uint32_t set) {
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i)
        if (leader_sets[i] == set)
            return leader_set_type[i];
    return 2; // Follower
}

void InitReplacementState() {
    // RRIP, SHiP, streaming detector
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        last_addr[set] = 0;
        stream_ctr[set] = 0;
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            rrpv[set][way] = 2; // Default distant
            block_sig[set][way] = 0;
            block_outcome[set][way] = 0;
        }
    }
    // SHiP outcome table
    for (uint32_t i = 0; i < SHIP_TABLE_SIZE; ++i)
        ship_table[i].outcome = 1; // Neutral

    // Leader sets: evenly spread across LLC_SETS
    leader_sets.clear();
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i) {
        uint32_t set = (i * LLC_SETS) / NUM_LEADER_SETS;
        leader_sets.push_back(set);
        leader_set_type[i] = (i < NUM_LEADER_SETS / 2) ? 0 : 1; // First half SHiP, second half RRIP
    }
    PSEL = 512;
}

// Streaming detector: update per access
inline void UpdateStreaming(uint32_t set, uint64_t paddr) {
    uint16_t addr_lo = paddr & 0xFFFF;
    uint16_t delta = addr_lo - last_addr[set];
    if (delta == 64 || delta == -64) { // Typical cache line stride
        if (stream_ctr[set] < 3) stream_ctr[set]++;
    } else {
        if (stream_ctr[set] > 0) stream_ctr[set]--;
    }
    last_addr[set] = addr_lo;
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
    // Prefer invalid block
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (!current_set[way].valid)
            return way;

    // Streaming bypass: if streaming confidence high, pick RRPV=3 block or random
    if (stream_ctr[set] == 3) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        // Fallback: pick random
        return rand() % LLC_WAYS;
    }

    // SHiP-aware RRIP victim selection: prefer RRPV=3, then increment RRPVs
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] < 3)
                rrpv[set][way]++;
    }
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
    UpdateStreaming(set, paddr);

    // --- SHiP signature ---
    uint8_t sig = GetSignature(PC);
    uint32_t ship_idx = SHIPIndex(sig);

    // --- SHiP outcome update ---
    if (hit) {
        block_outcome[set][way] = 3; // Strong reuse
        ship_table[ship_idx].outcome = std::min(ship_table[ship_idx].outcome + 1, 3);
    } else {
        // On miss, decay outcome for victim block's signature
        uint8_t victim_sig = block_sig[set][way];
        uint32_t victim_idx = SHIPIndex(victim_sig);
        if (ship_table[victim_idx].outcome > 0)
            ship_table[victim_idx].outcome--;
    }

    // --- Set-dueling: leader sets update PSEL ---
    uint8_t set_type = GetSetType(set);
    if (!hit && set_type < 2) {
        if (set_type == 0) { // SHiP leader miss: increment PSEL
            if (PSEL < ((1 << PSEL_BITS) - 1)) PSEL++;
        } else if (set_type == 1) { // RRIP leader miss: decrement PSEL
            if (PSEL > 0) PSEL--;
        }
    }

    // --- Insertion policy ---
    uint8_t insert_rrpv = 2; // Default distant
    if (stream_ctr[set] == 3) {
        // Streaming detected: insert at distant or bypass
        insert_rrpv = 3; // Bypass: never reused
    } else if (set_type == 0) { // SHiP leader
        insert_rrpv = (ship_table[ship_idx].outcome >= 2) ? 0 : 2;
    } else if (set_type == 1) { // RRIP leader
        insert_rrpv = 2;
    } else { // Follower
        insert_rrpv = (PSEL >= 512) ?
            ((ship_table[ship_idx].outcome >= 2) ? 0 : 2) :
            2;
    }

    rrpv[set][way] = insert_rrpv;
    block_sig[set][way] = sig;
    block_outcome[set][way] = hit ? 3 : 0;
}

// Print end-of-simulation statistics
void PrintStats() {
    int streaming_sets = 0;
    int reused_blocks = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        if (stream_ctr[set] == 3) streaming_sets++;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (block_outcome[set][way] == 3) reused_blocks++;
    std::cout << "SHiP-SB Policy: SHiP-lite + Streaming Bypass Hybrid" << std::endl;
    std::cout << "Streaming sets: " << streaming_sets << "/" << LLC_SETS << std::endl;
    std::cout << "Strongly reused blocks: " << reused_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "PSEL: " << PSEL << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    int streaming_sets = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        if (stream_ctr[set] == 3) streaming_sets++;
    std::cout << "Streaming sets (heartbeat): " << streaming_sets << "/" << LLC_SETS << std::endl;
}