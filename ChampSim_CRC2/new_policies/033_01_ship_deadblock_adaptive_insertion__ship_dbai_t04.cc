#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// ---- RRIP Metadata ----
uint8_t rrpv[LLC_SETS][LLC_WAYS]; // 2 bits per block

// ---- SHiP-lite: per-line PC signature (6 bits) ----
uint8_t pc_sig[LLC_SETS][LLC_WAYS]; // 6 bits per block

// ---- Dead-block counter: per-line, 2 bits ----
uint8_t dead_ctr[LLC_SETS][LLC_WAYS]; // 2 bits per block

// ---- SHiP outcome table: 4096 entries, 2 bits each ----
#define SHIP_ENTRIES 4096
uint8_t ship_ctr[SHIP_ENTRIES]; // 2 bits per entry

// ---- Streaming detector: per-set monotonicity ----
uint64_t last_addr[LLC_SETS]; // 48 bits per set (paddr)
uint8_t stream_score[LLC_SETS]; // 2 bits per set

// ---- Other bookkeeping ----
uint64_t access_counter = 0;
#define DECAY_PERIOD 100000

// Helper: hash PC to 6 bits
inline uint16_t get_pc_sig(uint64_t PC) {
    return (PC ^ (PC >> 6) ^ (PC >> 12)) & 0x3F; // 6 bits
}

// Helper: hash PC to SHiP table index (12 bits)
inline uint16_t get_ship_idx(uint64_t PC) {
    return (PC ^ (PC >> 13) ^ (PC >> 23)) & 0xFFF; // 12 bits
}

void InitReplacementState() {
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            rrpv[set][way] = 3;
            pc_sig[set][way] = 0;
            dead_ctr[set][way] = 0;
        }
        last_addr[set] = 0;
        stream_score[set] = 0;
    }
    for (uint32_t i = 0; i < SHIP_ENTRIES; ++i)
        ship_ctr[i] = 1; // weakly dead
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

    // ---- Streaming detector ----
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

    // ---- SHiP signature and outcome update ----
    uint16_t sig = get_pc_sig(PC);
    uint16_t ship_idx = get_ship_idx(PC);

    // Dead-block approximation: if victim was not reused, penalize signature
    if (!hit) {
        // If victim block's dead_ctr is zero (not reused), penalize its signature
        for (uint32_t vway = 0; vway < LLC_WAYS; ++vway) {
            if (current_set[vway].valid && current_set[vway].address == victim_addr) {
                if (dead_ctr[set][vway] == 0) {
                    uint16_t victim_sig = pc_sig[set][vway];
                    uint16_t victim_idx = get_ship_idx(victim_sig);
                    if (ship_ctr[victim_idx] > 0)
                        ship_ctr[victim_idx]--;
                }
                break;
            }
        }
    }

    // On hit, increase reuse confidence for this signature
    if (hit) {
        if (ship_ctr[ship_idx] < 3)
            ship_ctr[ship_idx]++;
        rrpv[set][way] = 0; // promote to MRU
        if (dead_ctr[set][way] < 3)
            dead_ctr[set][way]++;
    } else {
        if (ship_ctr[ship_idx] > 0)
            ship_ctr[ship_idx]--;
        dead_ctr[set][way] = 0; // reset on miss
    }
    pc_sig[set][way] = sig;

    // ---- Insertion policy ----
    if (streaming) {
        // Streaming detected: bypass (set RRPV=3)
        rrpv[set][way] = 3;
        dead_ctr[set][way] = 0;
    } else {
        // SHiP outcome: insert at MRU if high reuse, else at distant RRPV
        if (ship_ctr[ship_idx] >= 2) {
            rrpv[set][way] = 0; // high reuse, insert at MRU
            dead_ctr[set][way] = 1; // optimistic reuse
        } else {
            rrpv[set][way] = 2; // low reuse, insert at distant RRPV
            dead_ctr[set][way] = 0;
        }
    }

    // ---- Periodic decay of SHiP outcome counters ----
    if (access_counter % DECAY_PERIOD == 0) {
        for (uint32_t i = 0; i < SHIP_ENTRIES; ++i)
            if (ship_ctr[i] > 0)
                ship_ctr[i]--;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    int high_reuse_sigs = 0;
    for (uint32_t i = 0; i < SHIP_ENTRIES; ++i)
        if (ship_ctr[i] >= 2) high_reuse_sigs++;
    int streaming_sets = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        if (stream_score[set] >= 2) streaming_sets++;
    int dead_blocks = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (dead_ctr[set][way] == 0) dead_blocks++;
    std::cout << "SHiP-DBAI Policy: SHiP-Lite + Dead-block Approximation + Streaming Bypass" << std::endl;
    std::cout << "High-reuse signatures: " << high_reuse_sigs << "/" << SHIP_ENTRIES << std::endl;
    std::cout << "Streaming sets (score>=2): " << streaming_sets << "/" << LLC_SETS << std::endl;
    std::cout << "Dead blocks (dead_ctr==0): " << dead_blocks << "/" << (LLC_SETS*LLC_WAYS) << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    int high_reuse_sigs = 0;
    for (uint32_t i = 0; i < SHIP_ENTRIES; ++i)
        if (ship_ctr[i] >= 2) high_reuse_sigs++;
    int streaming_sets = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        if (stream_score[set] >= 2) streaming_sets++;
    int dead_blocks = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (dead_ctr[set][way] == 0) dead_blocks++;
    std::cout << "High-reuse signatures (heartbeat): " << high_reuse_sigs << "/" << SHIP_ENTRIES << std::endl;
    std::cout << "Streaming sets (heartbeat): " << streaming_sets << "/" << LLC_SETS << std::endl;
    std::cout << "Dead blocks (heartbeat): " << dead_blocks << "/" << (LLC_SETS*LLC_WAYS) << std::endl;
}