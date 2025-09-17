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

// ---- SHiP-Lite: 5-bit PC signature per block, global table 2048 entries (2 bits each) ----
#define SHIP_SIG_BITS 5
#define SHIP_TABLE_SIZE 2048
uint8_t ship_sig[LLC_SETS][LLC_WAYS]; // 5 bits per block
uint8_t ship_table[SHIP_TABLE_SIZE];  // 2 bits per signature

// ---- Streaming Detector: 2 bits per set ----
uint8_t stream_state[LLC_SETS]; // 2 bits per set
uint64_t last_addr[LLC_SETS];   // last address per set

// ---- DRRIP set-dueling ----
#define PSEL_BITS 10
#define PSEL_MAX ((1 << PSEL_BITS) - 1)
uint16_t psel = PSEL_MAX / 2;

#define NUM_LEADER_SETS 64
#define SRRIP_LEADER_SETS 32
#define BRRIP_LEADER_SETS 32
uint8_t leader_set_type[NUM_LEADER_SETS]; // 0: SRRIP, 1: BRRIP
uint8_t set_leader_map[LLC_SETS];         // LLC set to leader set mapping

// ---- Other bookkeeping ----
uint64_t access_counter = 0;
#define STREAM_DELTA_MAX 128 // threshold for monotonic stride
#define STREAM_DETECT_WINDOW 32

void InitReplacementState() {
    // RRIP and SHiP
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        stream_state[set] = 0;
        last_addr[set] = 0;
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            rrpv[set][way] = 2; // SRRIP default
            ship_sig[set][way] = 0;
        }
    }
    memset(ship_table, 1, sizeof(ship_table)); // initialize to weak reuse

    // Leader sets
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i)
        leader_set_type[i] = (i < SRRIP_LEADER_SETS) ? 0 : 1;
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        if (set % (LLC_SETS / NUM_LEADER_SETS) == 0)
            set_leader_map[set] = set / (LLC_SETS / NUM_LEADER_SETS);
        else
            set_leader_map[set] = 0xFF;
    }
    psel = PSEL_MAX / 2;
    access_counter = 0;
}

// Find victim: RRIP policy
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

    // --- SHiP signature ---
    uint8_t sig = (PC ^ (PC >> 5) ^ (PC >> 10)) & ((1 << SHIP_SIG_BITS)-1); // 5-bit signature
    ship_sig[set][way] = sig;

    // --- SHiP table update ---
    uint32_t table_idx = sig;
    if (hit) {
        if (ship_table[table_idx] < 3) ship_table[table_idx]++;
    } else {
        if (ship_table[table_idx] > 0) ship_table[table_idx]--;
    }

    // --- Streaming detector ---
    uint64_t delta = (last_addr[set] > 0) ? std::abs((int64_t)paddr - (int64_t)last_addr[set]) : 0;
    last_addr[set] = paddr;
    // Detect near-monotonic stride (delta within STREAM_DELTA_MAX, same direction)
    if (delta > 0 && delta <= STREAM_DELTA_MAX) {
        if (stream_state[set] < 3) stream_state[set]++;
    } else {
        if (stream_state[set] > 0) stream_state[set]--;
    }
    bool streaming = (stream_state[set] >= 2);

    // --- DRRIP set-dueling ---
    uint8_t leader_idx = set_leader_map[set];
    bool is_leader = (leader_idx != 0xFF);
    bool use_brrip = false;
    if (is_leader) {
        use_brrip = (leader_set_type[leader_idx] == 1);
    } else {
        use_brrip = (psel >= (PSEL_MAX / 2));
    }

    // --- Insertion policy ---
    if (streaming) {
        // Streaming detected: bypass or insert at LRU
        rrpv[set][way] = 3;
    }
    else if (ship_table[table_idx] == 0) {
        // Signature shows poor reuse: insert at LRU
        rrpv[set][way] = 3;
    }
    else {
        // DRRIP insertion
        if (use_brrip) {
            if ((access_counter & 0x1F) == 0)
                rrpv[set][way] = 0;
            else
                rrpv[set][way] = 2;
        } else {
            rrpv[set][way] = 2;
        }
    }

    // On hit: promote to MRU
    if (hit)
        rrpv[set][way] = 0;

    // --- PSEL adjustment for leader sets ---
    if (is_leader && !hit) {
        if (leader_set_type[leader_idx] == 0) {
            if (psel < PSEL_MAX) psel++;
        } else {
            if (psel > 0) psel--;
        }
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    int streaming_sets = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        if (stream_state[set] >= 2) streaming_sets++;
    int high_reuse = 0;
    for (uint32_t i = 0; i < SHIP_TABLE_SIZE; ++i)
        if (ship_table[i] >= 2) high_reuse++;
    std::cout << "SHiP-Lite + Streaming Bypass DRRIP Hybrid" << std::endl;
    std::cout << "Streaming sets (stream_state>=2): " << streaming_sets << "/" << LLC_SETS << std::endl;
    std::cout << "High-reuse SHiP signatures: " << high_reuse << "/" << SHIP_TABLE_SIZE << std::endl;
    std::cout << "PSEL value: " << psel << " (max " << PSEL_MAX << ")" << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    int streaming_sets = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        if (stream_state[set] >= 2) streaming_sets++;
    std::cout << "Streaming sets (heartbeat): " << streaming_sets << "/" << LLC_SETS << std::endl;
    std::cout << "PSEL (heartbeat): " << psel << std::endl;
}