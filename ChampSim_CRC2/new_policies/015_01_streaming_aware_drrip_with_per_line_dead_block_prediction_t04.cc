#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- DRRIP Metadata ---
static uint8_t is_brrip_leader[LLC_SETS]; // 1 bit per set (SRRIP/BRRIP leader sets)
static uint16_t psel = 512; // 10 bits, mid-value

// --- RRPV bits ---
static uint8_t rrpv[LLC_SETS][LLC_WAYS]; // 2 bits per line

// --- Dead-block predictor: 2 bits per line ---
static uint8_t dead_counter[LLC_SETS][LLC_WAYS]; // 2 bits per line

// --- Streaming detector: per-set address delta ---
static uint64_t last_addr[LLC_SETS];     // last accessed address per set
static int64_t last_delta[LLC_SETS];     // last delta per set
static uint8_t stream_conf[LLC_SETS];    // streaming confidence (2 bits per set)

// --- Initialization ---
void InitReplacementState() {
    memset(is_brrip_leader, 0, sizeof(is_brrip_leader));
    memset(rrpv, 3, sizeof(rrpv));
    memset(dead_counter, 0, sizeof(dead_counter));
    memset(last_addr, 0, sizeof(last_addr));
    memset(last_delta, 0, sizeof(last_delta));
    memset(stream_conf, 0, sizeof(stream_conf));

    // DRRIP: Assign 32 leader sets to SRRIP (low indices), 32 to BRRIP (high indices)
    for (uint32_t i = 0; i < LLC_SETS; ++i) {
        if (i < 32) is_brrip_leader[i] = 0; // SRRIP leader
        else if (i >= LLC_SETS - 32) is_brrip_leader[i] = 1; // BRRIP leader
        // else: follower
    }
    psel = 512;
}

// --- Find victim: Prefer dead blocks, else RRIP ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Prefer blocks predicted dead (dead_counter == 0)
    for (uint32_t way = 0; way < LLC_WAYS; ++way) {
        if (dead_counter[set][way] == 0)
            return way;
    }
    // Otherwise, standard RRIP victim selection
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
    // --- Streaming detector ---
    int64_t delta = (int64_t)paddr - (int64_t)last_addr[set];
    if (delta == last_delta[set] && delta != 0) {
        if (stream_conf[set] < 3) ++stream_conf[set];
    } else {
        if (stream_conf[set] > 0) --stream_conf[set];
    }
    last_delta[set] = delta;
    last_addr[set] = paddr;

    // --- Dead-block predictor update ---
    if (hit) {
        // On hit: block reused, increment dead_counter (max 3)
        if (dead_counter[set][way] < 3) ++dead_counter[set][way];
        rrpv[set][way] = 0; // Promote to MRU
        return;
    } else {
        // On eviction: decrement dead_counter for victim
        if (dead_counter[set][way] > 0) --dead_counter[set][way];
    }

    // --- DRRIP insertion depth ---
    uint8_t insert_rrpv = 2; // default: SRRIP (insert at RRPV=2)
    bool br_insert = false;
    if (is_brrip_leader[set] == 1) {
        // BRRIP leader: insert at distant (RRPV=2) most times, MRU only 1/32
        br_insert = ((rand() & 31) == 0);
        insert_rrpv = br_insert ? 0 : 2;
    } else if (is_brrip_leader[set] == 0) {
        // SRRIP leader: always insert at RRPV=2
        insert_rrpv = 2;
    } else {
        // Follower: PSEL controls
        if (psel >= 512) {
            // SRRIP preferred
            insert_rrpv = 2;
        } else {
            br_insert = ((rand() & 31) == 0);
            insert_rrpv = br_insert ? 0 : 2;
        }
    }

    // --- Streaming-aware bypass/insertion ---
    if (stream_conf[set] >= 2) {
        // Detected streaming: insert at distant RRPV (3), or bypass (optional)
        insert_rrpv = 3;
    }

    rrpv[set][way] = insert_rrpv;
    dead_counter[set][way] = 2; // Reset dead-counter for new block (neutral)

    // --- DRRIP: update PSEL based on misses in leader sets
    if (is_brrip_leader[set] == 1 && !hit) {
        if (psel > 0) --psel;
    } else if (is_brrip_leader[set] == 0 && !hit) {
        if (psel < 1023) ++psel;
    }

    // --- Periodic dead-counter decay (optional, every 4096 fills) ---
    static uint64_t fill_count = 0;
    if (++fill_count % (LLC_SETS * LLC_WAYS / 8) == 0) {
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            for (uint32_t w = 0; w < LLC_WAYS; ++w)
                if (dead_counter[s][w] > 0) --dead_counter[s][w];
    }
}

// --- Print end-of-simulation statistics ---
void PrintStats() {
    std::cout << "Streaming-Aware DRRIP + Dead-Block Policy\n";
    std::cout << "PSEL: " << psel << std::endl;
    // Dead-counter histogram
    uint32_t hist[4] = {0,0,0,0};
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        for (uint32_t w = 0; w < LLC_WAYS; ++w)
            hist[dead_counter[s][w]]++;
    std::cout << "Dead-counter histogram: ";
    for (int i=0; i<4; ++i) std::cout << hist[i] << " ";
    std::cout << std::endl;
}

// --- Print periodic (heartbeat) statistics ---
void PrintStats_Heartbeat() {
    // No-op for brevity
}