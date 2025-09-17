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
#define NUM_LEADER_SETS 32 // 16 for SRRIP, 16 for BRRIP

// --- Streaming detector parameters ---
#define STREAM_DETECT_LEN 4
#define STREAM_DELTA_BITS 16

// --- Metadata structures ---
struct LineMeta {
    uint8_t rrpv; // 2 bits
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
std::vector<uint32_t> leader_sets_srrip;
std::vector<uint32_t> leader_sets_brrip;

// --- Helper functions ---
void init_leader_sets() {
    // Evenly distribute leader sets
    leader_sets_srrip.clear();
    leader_sets_brrip.clear();
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i) {
        leader_sets_srrip.push_back(i);
        leader_sets_brrip.push_back(i + NUM_LEADER_SETS);
    }
}

// --- Initialization ---
void InitReplacementState() {
    memset(line_meta, 0, sizeof(line_meta));
    memset(stream_table, 0, sizeof(stream_table));
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            line_meta[set][way].rrpv = RRPV_MAX;
    psel = PSEL_MAX / 2;
    init_leader_sets();
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

// --- DRRIP insertion policy ---
enum InsertPolicy { SRRIP, BRRIP };

InsertPolicy get_insertion_policy(uint32_t set) {
    // Leader sets: fixed policy
    for (auto s : leader_sets_srrip)
        if (set == s) return SRRIP;
    for (auto s : leader_sets_brrip)
        if (set == s) return BRRIP;
    // Other sets: dynamic
    return (psel >= (PSEL_MAX / 2)) ? SRRIP : BRRIP;
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
    // Should not reach here
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

    // DRRIP insertion policy
    InsertPolicy policy = get_insertion_policy(set);

    // On fill (miss)
    if (!hit) {
        if (streaming) {
            // Streaming block: bypass (do not insert, set RRPV to MAX so it is immediately evictable)
            line_meta[set][way].rrpv = RRPV_MAX;
        } else {
            // DRRIP insertion
            if (policy == SRRIP) {
                line_meta[set][way].rrpv = RRPV_MAX; // distant
            } else { // BRRIP
                // Insert at distant most of the time, MRU rarely (1/32)
                static uint32_t fill_count = 0;
                fill_count++;
                if ((fill_count & 0x1F) == 0)
                    line_meta[set][way].rrpv = 0; // MRU
                else
                    line_meta[set][way].rrpv = RRPV_MAX;
            }
        }
    } else {
        // On hit: promote to MRU
        line_meta[set][way].rrpv = 0;
    }

    // DRRIP set-dueling: update PSEL on leader sets
    bool is_leader_srrip = false, is_leader_brrip = false;
    for (auto s : leader_sets_srrip)
        if (set == s) is_leader_srrip = true;
    for (auto s : leader_sets_brrip)
        if (set == s) is_leader_brrip = true;

    if (!hit) {
        if (is_leader_srrip && psel > 0)
            psel--;
        else if (is_leader_brrip && psel < PSEL_MAX)
            psel++;
    }
}

// --- Stats ---
void PrintStats() {
    std::cout << "ADSB Policy: Adaptive DRRIP with Streaming Bypass" << std::endl;
    std::cout << "PSEL final value: " << psel << std::endl;
}
void PrintStats_Heartbeat() {}