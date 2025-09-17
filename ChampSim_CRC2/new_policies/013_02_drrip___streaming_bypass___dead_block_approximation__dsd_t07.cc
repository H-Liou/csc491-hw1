#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- DRRIP Metadata ---
static uint8_t rrpv[LLC_SETS][LLC_WAYS]; // 2 bits per line
static uint8_t is_brrip_leader[LLC_SETS]; // 1 bit per set (SRRIP/BRRIP leader sets)
static uint16_t psel = 512; // 10 bits, mid-value

// --- Streaming Detector ---
static uint64_t last_addr[LLC_SETS];
static int64_t last_delta[LLC_SETS];
static uint8_t stream_ctr[LLC_SETS]; // 2 bits per set

// --- Per-line Dead-block Approximation ---
static uint8_t dead_bit[LLC_SETS][LLC_WAYS]; // 1 bit per line

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv)); // Insert distant by default
    memset(is_brrip_leader, 0, sizeof(is_brrip_leader));
    memset(last_addr, 0, sizeof(last_addr));
    memset(last_delta, 0, sizeof(last_delta));
    memset(stream_ctr, 0, sizeof(stream_ctr));
    memset(dead_bit, 0, sizeof(dead_bit));

    // Assign 64 leader sets to SRRIP (low indices), 64 to BRRIP (high indices)
    for (uint32_t i = 0; i < LLC_SETS; ++i) {
        if (i < 64) is_brrip_leader[i] = 0; // SRRIP leader
        else if (i >= LLC_SETS - 64) is_brrip_leader[i] = 1; // BRRIP leader
        // else: follower
    }
    psel = 512; // Start in the middle
}

// --- Streaming Detector ---
inline bool IsStreaming(uint32_t set, uint64_t paddr) {
    int64_t delta = paddr - last_addr[set];
    bool streaming = false;
    if (last_delta[set] != 0 && delta == last_delta[set]) {
        if (stream_ctr[set] < 3) ++stream_ctr[set];
    } else {
        if (stream_ctr[set] > 0) --stream_ctr[set];
    }
    streaming = (stream_ctr[set] >= 2);
    last_delta[set] = delta;
    last_addr[set] = paddr;
    return streaming;
}

// --- DRRIP Victim Selection ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // If any dead-bit line exists, evict it first (dead-block hint has highest priority)
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (dead_bit[set][way])
            return way;

    // Otherwise, standard SRRIP victim selection
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] < 3) ++rrpv[set][way];
    }
    return 0;
}

// --- Update Replacement State ---
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
    // --- Streaming detection ---
    bool streaming = IsStreaming(set, paddr);

    // --- Dead-block approximation ---
    // On hit: clear dead-bit and promote to MRU
    if (hit) {
        rrpv[set][way] = 0;
        dead_bit[set][way] = 0;
        return;
    }

    // On eviction: if the line was not reused, set dead-bit for that line
    if (dead_bit[set][way] == 0) {
        dead_bit[set][way] = 1;
    }

    // --- Insertion Policy (DRRIP + Streaming Bypass) ---
    uint8_t insert_rrpv;
    if (streaming) {
        // Streaming phase: always insert at distant RRPV and set dead-bit
        insert_rrpv = 3;
        dead_bit[set][way] = 1;
    } else {
        // DRRIP set-dueling: select between SRRIP and BRRIP
        if (is_brrip_leader[set] == 1) {
            // BRRIP leader: insert distant (RRPV=3) most of the time (1/32), else RRPV=2
            if ((rand() & 31) == 0)
                insert_rrpv = 3;
            else
                insert_rrpv = 2;
        } else if (is_brrip_leader[set] == 0) {
            // SRRIP leader: insert at RRPV=2 (long re-use), only occasionally MRU
            insert_rrpv = 2;
        } else {
            // Follower sets: select based on PSEL
            if (psel >= 512) {
                // SRRIP preferred
                insert_rrpv = 2;
            } else {
                // BRRIP preferred
                if ((rand() & 31) == 0)
                    insert_rrpv = 3;
                else
                    insert_rrpv = 2;
            }
        }
        dead_bit[set][way] = 0;
    }
    rrpv[set][way] = insert_rrpv;

    // --- DRRIP PSEL update for leader sets ---
    if (is_brrip_leader[set] == 1 && !hit) {
        if (psel > 0) psel--;
    } else if (is_brrip_leader[set] == 0 && !hit) {
        if (psel < 1023) psel++;
    }
}

// --- Print statistics ---
void PrintStats() {
    std::cout << "DSD Policy: DRRIP + Streaming Bypass + Dead-Block Approximation\n";
    // PSEL value
    std::cout << "DRRIP PSEL: " << psel << std::endl;
    // Dead-bit histogram
    uint32_t dead_hist[2] = {0,0};
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            dead_hist[dead_bit[set][way]]++;
    std::cout << "Dead-bit histogram: " << dead_hist[0] << " alive, " << dead_hist[1] << " dead\n";
    // Streaming counter histogram
    uint32_t stream_hist[4] = {0,0,0,0};
    for (uint32_t i = 0; i < LLC_SETS; ++i)
        stream_hist[stream_ctr[i]]++;
    std::cout << "Streaming counter histogram: ";
    for (int i=0; i<4; ++i) std::cout << stream_hist[i] << " ";
    std::cout << std::endl;
}

void PrintStats_Heartbeat() {}