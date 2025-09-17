#include <vector>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- RRIP state ---
uint8_t rrpv[LLC_SETS][LLC_WAYS]; // 2 bits per block

// --- SHiP-lite signature per block ---
uint8_t signature[LLC_SETS][LLC_WAYS]; // 6 bits per block

// --- SHiP-lite outcome table ---
#define SHIP_SIG_BITS 6
#define SHIP_TABLE_SIZE (1 << SHIP_SIG_BITS)
uint8_t ship_table[SHIP_TABLE_SIZE]; // 2 bits per signature

// --- Set-dueling streaming bypass ---
#define NUM_LEADER_SETS 32
uint8_t is_stream_leader[LLC_SETS]; // 0: normal, 1: stream leader, 2: SRRIP leader
uint16_t psel = 512; // 10 bits

// --- Streaming detector: per-set monotonicity ---
uint64_t last_addr[LLC_SETS]; // 48 bits per set
uint8_t stream_score[LLC_SETS]; // 2 bits per set

// --- Other bookkeeping ---
uint64_t access_counter = 0;
#define DECAY_PERIOD 100000

void InitReplacementState() {
    // Assign leader sets for set-dueling
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        is_stream_leader[set] = 0;
    }
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i) {
        is_stream_leader[i] = 1; // streaming bypass leader
        is_stream_leader[LLC_SETS - 1 - i] = 2; // SRRIP leader
    }
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            rrpv[set][way] = 3;
            signature[set][way] = 0;
        }
        last_addr[set] = 0;
        stream_score[set] = 0;
    }
    for (uint32_t i = 0; i < SHIP_TABLE_SIZE; ++i)
        ship_table[i] = 1; // weakly dead
    psel = 512;
    access_counter = 0;
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

    // RRIP: select block with max RRPV (3)
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
    access_counter++;

    // --- Streaming detector ---
    uint64_t last = last_addr[set];
    uint8_t score = stream_score[set];
    if (last == 0) {
        last_addr[set] = paddr;
        stream_score[set] = 0;
    } else {
        uint64_t delta = (paddr > last) ? (paddr - last) : (last - paddr);
        if (delta == 64 || delta == 128) { // 1-2 block stride
            if (score < 3) stream_score[set]++;
        } else {
            if (score > 0) stream_score[set]--;
        }
        last_addr[set] = paddr;
    }
    bool streaming = (stream_score[set] >= 2);

    // --- SHiP-lite signature ---
    uint8_t sig = (PC ^ (PC >> 6) ^ (PC >> 12)) & ((1 << SHIP_SIG_BITS) - 1);

    // --- Update SHiP outcome table ---
    if (hit) {
        if (ship_table[sig] < 3) ship_table[sig]++;
        rrpv[set][way] = 0; // promote to MRU
    } else {
        if (ship_table[sig] > 0) ship_table[sig]--;
    }

    // --- Insertion policy: set-dueling between streaming bypass and SHiP-SRRIP ---
    bool use_streaming = false;
    if (is_stream_leader[set] == 1) use_streaming = true;
    else if (is_stream_leader[set] == 2) use_streaming = false;
    else use_streaming = (psel >= 512);

    // --- Streaming bypass logic ---
    if (use_streaming && streaming) {
        // Streaming detected: insert at RRPV=3 (bypass)
        rrpv[set][way] = 3;
        // Update PSEL: if hit, streaming bypass is good; else, SRRIP is better
        if (is_stream_leader[set] == 1) {
            if (hit && psel < 1023) psel++;
            else if (!hit && psel > 0) psel--;
        }
    } else {
        // SHiP-lite: insert at MRU if high-reuse signature, else at distant RRPV
        if (ship_table[sig] >= 2)
            rrpv[set][way] = 0; // high reuse, insert at MRU
        else
            rrpv[set][way] = 2; // weakly dead, insert at distant RRPV

        // Update PSEL for SRRIP leader sets
        if (is_stream_leader[set] == 2) {
            if (hit && psel > 0) psel--;
            else if (!hit && psel < 1023) psel++;
        }
    }

    // --- Store signature ---
    signature[set][way] = sig;

    // --- Periodic decay of SHiP outcome table ---
    if (access_counter % DECAY_PERIOD == 0) {
        for (uint32_t i = 0; i < SHIP_TABLE_SIZE; ++i)
            if (ship_table[i] > 0) ship_table[i]--;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    int high_reuse_blocks = 0;
    for (uint32_t i = 0; i < SHIP_TABLE_SIZE; ++i)
        if (ship_table[i] >= 2) high_reuse_blocks++;
    int streaming_sets = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        if (stream_score[set] >= 2) streaming_sets++;
    std::cout << "SLSB Policy: SHiP-Lite + Set-Dueling Streaming Bypass" << std::endl;
    std::cout << "High-reuse signatures: " << high_reuse_blocks << "/" << SHIP_TABLE_SIZE << std::endl;
    std::cout << "Streaming sets (score>=2): " << streaming_sets << "/" << LLC_SETS << std::endl;
    std::cout << "PSEL selector: " << psel << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    int high_reuse_blocks = 0;
    for (uint32_t i = 0; i < SHIP_TABLE_SIZE; ++i)
        if (ship_table[i] >= 2) high_reuse_blocks++;
    int streaming_sets = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        if (stream_score[set] >= 2) streaming_sets++;
    std::cout << "High-reuse signatures (heartbeat): " << high_reuse_blocks << "/" << SHIP_TABLE_SIZE << std::endl;
    std::cout << "Streaming sets (heartbeat): " << streaming_sets << "/" << LLC_SETS << std::endl;
    std::cout << "PSEL selector (heartbeat): " << psel << std::endl;
}