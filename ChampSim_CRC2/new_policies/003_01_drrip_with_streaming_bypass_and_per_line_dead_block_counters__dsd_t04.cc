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
#define BRRIP_INSERT_PROB 32 // Insert at distant RRPV with 1/32 probability
#define PSEL_BITS 10
#define PSEL_MAX ((1 << PSEL_BITS) - 1)
#define NUM_LEADER_SETS 64

// --- Streaming detector parameters ---
#define STREAM_DETECT_LEN 4
#define STREAM_DELTA_BITS 16

// --- Dead-block counter ---
#define DEAD_BITS 2
#define DEAD_MAX ((1 << DEAD_BITS) - 1)

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

// --- DRRIP global state ---
uint16_t psel = PSEL_MAX / 2;
uint8_t leader_type[LLC_SETS]; // 0: SRRIP, 1: BRRIP
LineMeta line_meta[LLC_SETS][LLC_WAYS];
StreamDetector stream_table[LLC_SETS];

// --- Helper functions ---
void InitReplacementState() {
    memset(line_meta, 0, sizeof(line_meta));
    memset(stream_table, 0, sizeof(stream_table));
    memset(leader_type, 0, sizeof(leader_type));
    // Assign leader sets (even: SRRIP, odd: BRRIP)
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i) {
        uint32_t set = (i * LLC_SETS) / NUM_LEADER_SETS;
        leader_type[set] = (i % 2);
    }
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            line_meta[set][way].rrpv = RRPV_MAX;
            line_meta[set][way].dead = 0;
        }
}

// Streaming detector: monotonic stride detection
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

// DRRIP insertion policy selector
bool use_brrip(uint32_t set) {
    // Leader sets always use their assigned policy
    if (leader_type[set] == 0) return false; // SRRIP
    if (leader_type[set] == 1) return true;  // BRRIP
    // Non-leader sets: use global PSEL
    return (psel > (PSEL_MAX / 2));
}

// Victim selection: SRRIP
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (line_meta[set][way].rrpv == RRPV_MAX)
                return way;
        }
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (line_meta[set][way].rrpv < RRPV_MAX)
                line_meta[set][way].rrpv++;
        }
    }
    return 0;
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
    bool streaming = is_streaming(set, paddr);

    // On fill (miss)
    if (!hit) {
        // Streaming bypass: do not cache (set RRPV to MAX so it is immediately evictable)
        if (streaming) {
            line_meta[set][way].rrpv = RRPV_MAX;
        } else {
            // Dead-block penalty: if dead counter is high, insert at distant
            if (line_meta[set][way].dead >= DEAD_MAX) {
                line_meta[set][way].rrpv = RRPV_MAX;
            } else {
                // DRRIP insertion policy
                bool brrip = use_brrip(set);
                if (brrip) {
                    // BRRIP: insert at distant with low probability
                    if ((rand() % BRRIP_INSERT_PROB) == 0)
                        line_meta[set][way].rrpv = 0;
                    else
                        line_meta[set][way].rrpv = RRPV_MAX - 1;
                } else {
                    // SRRIP: insert at MRU
                    line_meta[set][way].rrpv = 0;
                }
            }
        }
        // Reset dead-block counter on fill
        line_meta[set][way].dead = 0;
    } else {
        // On hit: promote to MRU and reset dead counter
        line_meta[set][way].rrpv = 0;
        line_meta[set][way].dead = 0;
    }

    // On eviction: increment dead-block counter if not reused
    if (!hit && victim_addr != 0) {
        for (uint32_t vway = 0; vway < LLC_WAYS; ++vway) {
            // Champsim: current_set[vway].address == victim_addr
            // If you have access to current_set, you can match victim_addr
            // Here, we conservatively increment dead counter for all lines in set
            if (line_meta[set][vway].dead < DEAD_MAX)
                line_meta[set][vway].dead++;
        }
        // Update DRRIP PSEL for leader sets
        if (leader_type[set] == 0) {
            // SRRIP leader: increment PSEL if miss
            if (psel < PSEL_MAX) psel++;
        } else if (leader_type[set] == 1) {
            // BRRIP leader: decrement PSEL if miss
            if (psel > 0) psel--;
        }
    } else if (hit) {
        // Update DRRIP PSEL for leader sets on hit
        if (leader_type[set] == 0) {
            // SRRIP leader: decrement PSEL on hit
            if (psel > 0) psel--;
        } else if (leader_type[set] == 1) {
            // BRRIP leader: increment PSEL on hit
            if (psel < PSEL_MAX) psel++;
        }
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "DSD Policy: DRRIP + Streaming Bypass + Dead-block Counters" << std::endl;
    uint64_t dead_lines = 0, total_lines = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            total_lines++;
            if (line_meta[set][way].dead == DEAD_MAX)
                dead_lines++;
        }
    std::cout << "Fraction of lines with max dead-block penalty: "
              << (double)dead_lines / total_lines << std::endl;
    std::cout << "Final DRRIP PSEL value: " << psel << " (max " << PSEL_MAX << ")" << std::endl;
}

void PrintStats_Heartbeat() {}