#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- DRRIP parameters ---
#define RRPV_BITS 2
#define RRPV_MAX ((1 << RRPV_BITS) - 1)
#define PSEL_BITS 10
#define PSEL_MAX ((1 << PSEL_BITS) - 1)
#define NUM_LEADER_SETS 32

// --- Dead-block counter ---
#define DEAD_BITS 2

// --- Streaming detector parameters ---
#define STREAM_DETECT_LEN 4
#define STREAM_DELTA_BITS 16

// --- Metadata structures ---
struct LineMeta {
    uint8_t rrpv;      // 2 bits
    uint8_t dead;      // 2 bits
};

struct StreamDetector {
    uint16_t last_addr_low;
    uint16_t last_delta;
    uint8_t streak;
};

// --- Global state ---
LineMeta line_meta[LLC_SETS][LLC_WAYS];
StreamDetector stream_table[LLC_SETS];

// DRRIP set-dueling
uint16_t psel = PSEL_MAX / 2;
uint8_t leader_set_type[LLC_SETS]; // 0: SRRIP, 1: BRRIP, 2: follower

// --- Helper functions ---
void InitLeaderSets() {
    // Assign NUM_LEADER_SETS/2 sets to SRRIP, NUM_LEADER_SETS/2 to BRRIP, rest are followers
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        leader_set_type[set] = 2; // follower
    for (uint32_t i = 0; i < NUM_LEADER_SETS / 2; ++i)
        leader_set_type[i] = 0; // SRRIP leader
    for (uint32_t i = NUM_LEADER_SETS / 2; i < NUM_LEADER_SETS; ++i)
        leader_set_type[i] = 1; // BRRIP leader
}

// --- Initialization ---
void InitReplacementState() {
    memset(line_meta, 0, sizeof(line_meta));
    memset(stream_table, 0, sizeof(stream_table));
    InitLeaderSets();
    psel = PSEL_MAX / 2;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            line_meta[set][way].rrpv = RRPV_MAX;
            line_meta[set][way].dead = 1; // neutral start
        }
}

// --- Streaming detector ---
bool is_streaming(uint32_t set, uint64_t paddr) {
    StreamDetector &sd = stream_table[set];
    uint16_t addr_low = paddr & 0xFFFF;
    uint16_t delta = addr_low - sd.last_addr_low;
    bool streaming = false;

    if (sd.streak == 0) {
        sd.last_delta = delta;
        sd.streak = 1;
    } else if (delta == sd.last_delta && delta != 0) {
        sd.streak++;
        if (sd.streak >= STREAM_DETECT_LEN)
            streaming = true;
    } else {
        sd.last_delta = delta;
        sd.streak = 1;
    }
    sd.last_addr_low = addr_low;
    return streaming;
}

// --- DRRIP insertion depth ---
uint8_t get_insertion_rrpv(uint32_t set) {
    // Leader sets: fixed policy, followers: use PSEL
    if (leader_set_type[set] == 0) // SRRIP leader
        return 2; // SRRIP: insert at RRPV=2
    else if (leader_set_type[set] == 1) // BRRIP leader
        return (rand() % 32 == 0) ? 2 : RRPV_MAX; // BRRIP: insert at RRPV=2 with low probability
    else // follower
        return (psel >= (PSEL_MAX / 2)) ? ((rand() % 32 == 0) ? 2 : RRPV_MAX) : 2;
}

// --- Victim selection: SRRIP ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Find block with RRPV==MAX
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (line_meta[set][way].rrpv == RRPV_MAX)
                return way;
        }
        // Increment all RRPVs
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (line_meta[set][way].rrpv < RRPV_MAX)
                line_meta[set][way].rrpv++;
        }
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
    // Streaming detection
    bool streaming = is_streaming(set, paddr);

    // On fill (miss)
    if (!hit) {
        if (streaming) {
            // Streaming block: bypass (set RRPV to MAX so it is immediately evictable)
            line_meta[set][way].rrpv = RRPV_MAX;
        } else {
            // DRRIP insertion depth, but bias for dead-blocks
            uint8_t base_rrpv = get_insertion_rrpv(set);
            // If dead-block counter is high, insert at distant RRPV
            if (line_meta[set][way].dead >= 2)
                line_meta[set][way].rrpv = RRPV_MAX;
            else
                line_meta[set][way].rrpv = base_rrpv;
        }
        // Reset dead-block counter on fill
        line_meta[set][way].dead = 1;
    } else {
        // On hit: promote to MRU
        line_meta[set][way].rrpv = 0;
        // Decrease dead-block counter (improves reuse prediction)
        if (line_meta[set][way].dead > 0)
            line_meta[set][way].dead--;
    }

    // On eviction, decay dead-block counter for all lines in set (approximate dead-block)
    if (!hit && victim_addr != 0) {
        for (uint32_t vway = 0; vway < LLC_WAYS; ++vway) {
            if (line_meta[set][vway].dead < 3)
                line_meta[set][vway].dead++;
        }
    }

    // DRRIP set-dueling: update PSEL on leader sets
    if (leader_set_type[set] == 0) { // SRRIP leader
        if (hit && psel < PSEL_MAX)
            psel++;
    } else if (leader_set_type[set] == 1) { // BRRIP leader
        if (hit && psel > 0)
            psel--;
    }
}

// --- Stats ---
void PrintStats() {
    std::cout << "DSD Policy: DRRIP + Streaming Bypass + Dead-Block Decay" << std::endl;
    // Optionally print dead-block counter histogram
    uint64_t total_lines = 0, dead_lines = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            total_lines++;
            if (line_meta[set][way].dead >= 2)
                dead_lines++;
        }
    std::cout << "Fraction of lines predicted dead: "
              << (double)dead_lines / total_lines << std::endl;
    std::cout << "PSEL value: " << psel << std::endl;
}
void PrintStats_Heartbeat() {}