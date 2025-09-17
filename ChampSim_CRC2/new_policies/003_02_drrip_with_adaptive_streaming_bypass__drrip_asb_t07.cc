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
#define NUM_LEADER_SETS 64

// --- Streaming detector parameters ---
#define STREAM_DETECT_LEN 4

// --- Metadata structures ---
struct LineMeta {
    uint8_t rrpv;     // 2 bits
    bool is_leader;   // 1 bit
    bool leader_type; // 0: SRRIP, 1: BRRIP
};

struct StreamDetector {
    uint32_t last_addr_low;
    uint32_t last_delta;
    uint8_t streak;
};

// --- Global state ---
LineMeta line_meta[LLC_SETS][LLC_WAYS];
StreamDetector stream_table[LLC_SETS];
uint16_t leader_sets[NUM_LEADER_SETS]; // set indices
uint32_t leader_set_types[NUM_LEADER_SETS]; // 0: SRRIP, 1: BRRIP
uint16_t psel; // 10 bits

// Helper to initialize leader sets (spread evenly)
void init_leader_sets() {
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i) {
        leader_sets[i] = ((LLC_SETS / NUM_LEADER_SETS) * i) % LLC_SETS;
        leader_set_types[i] = (i < NUM_LEADER_SETS/2) ? 0 : 1;
    }
}

// --- Initialization ---
void InitReplacementState() {
    memset(line_meta, 0, sizeof(line_meta));
    memset(stream_table, 0, sizeof(stream_table));
    init_leader_sets();
    psel = PSEL_MAX / 2; // neutral start

    // Mark leader sets/ways
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            line_meta[set][way].rrpv = RRPV_MAX;
            line_meta[set][way].is_leader = false;
            line_meta[set][way].leader_type = false;
        }
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i) {
        uint32_t set = leader_sets[i];
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            line_meta[set][way].is_leader = true;
            line_meta[set][way].leader_type = leader_set_types[i];
        }
    }
}

// --- Streaming detector ---
bool is_streaming(uint32_t set, uint64_t paddr) {
    StreamDetector &sd = stream_table[set];
    uint32_t addr_low = paddr & 0xFFFFF; // lower bits, ~1MB window
    uint32_t delta = addr_low - sd.last_addr_low;
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
    bool streaming = is_streaming(set, paddr);

    // Determine leader set status
    bool is_leader = line_meta[set][way].is_leader;
    bool leader_type = line_meta[set][way].leader_type;

    // On fill (miss)
    if (!hit) {
        // Streaming: bypass (insert with RRPV MAX so evicted ASAP)
        if (streaming) {
            line_meta[set][way].rrpv = RRPV_MAX;
        } else if (is_leader) {
            // Leader sets: fixed insertion
            if (leader_type == 0) // SRRIP
                line_meta[set][way].rrpv = 1;
            else // BRRIP: Insert at distant RRPV_MAX with low probability
                line_meta[set][way].rrpv = (rand() % 32 == 0) ? 1 : RRPV_MAX;
        } else {
            // Follower sets: use PSEL to select policy
            if (psel >= (PSEL_MAX / 2))
                line_meta[set][way].rrpv = 1; // SRRIP
            else
                line_meta[set][way].rrpv = (rand() % 32 == 0) ? 1 : RRPV_MAX; // BRRIP
        }
    } else {
        // On hit: promote to MRU
        line_meta[set][way].rrpv = 0;
    }

    // PSEL update for leader sets (on miss/eviction only)
    if (is_leader && !hit) {
        // If leader_type == 0 (SRRIP) and hit, increment PSEL; if miss, decrement
        // For BRRIP, opposite
        if (leader_type == 0) { // SRRIP
            if (hit && psel < PSEL_MAX)
                psel++;
            else if (!hit && psel > 0)
                psel--;
        } else { // BRRIP
            if (hit && psel > 0)
                psel--;
            else if (!hit && psel < PSEL_MAX)
                psel++;
        }
    }
}

// --- Stats ---
void PrintStats() {
    std::cout << "DRRIP-ASB Policy: DRRIP with Adaptive Streaming Bypass" << std::endl;
    std::cout << "PSEL value: " << psel << " (SRRIP if high, BRRIP if low)" << std::endl;
    // Count fraction of blocks bypassed
    uint64_t total_lines = 0, streaming_lines = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            total_lines++;
            if (line_meta[set][way].rrpv == RRPV_MAX && is_streaming(set, 0))
                streaming_lines++;
        }
    std::cout << "Approx fraction of streaming-bypassed lines: "
              << (double)streaming_lines / total_lines << std::endl;
}
void PrintStats_Heartbeat() {}