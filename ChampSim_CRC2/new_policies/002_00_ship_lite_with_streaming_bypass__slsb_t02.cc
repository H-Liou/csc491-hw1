#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- SHiP-lite parameters ---
#define SHIP_SIG_BITS 6
#define SHIP_SIG_ENTRIES (1 << SHIP_SIG_BITS) // 64 entries
#define SHIP_OUTCOME_BITS 2 // 2-bit saturating counter

// --- RRIP parameters ---
#define RRPV_BITS 2
#define RRPV_MAX ((1 << RRPV_BITS) - 1)

// --- Streaming detector parameters ---
#define STREAM_DETECT_LEN 4

// --- Metadata structures ---
struct LineMeta {
    uint8_t rrpv; // 2 bits
    uint8_t ship_sig; // 6 bits
};

struct StreamDetector {
    uint16_t last_addr_low;
    uint16_t last_delta;
    uint8_t streak;
};

// --- SHiP outcome table ---
uint8_t ship_outcome[SHIP_SIG_ENTRIES]; // 2 bits per entry

// --- Per-set and per-line metadata ---
LineMeta line_meta[LLC_SETS][LLC_WAYS];
StreamDetector stream_table[LLC_SETS];

// --- Helper functions ---
uint8_t get_ship_sig(uint64_t PC) {
    // Hash PC to 6 bits (simple xor folding)
    return (uint8_t)(((PC >> 2) ^ (PC >> 8) ^ (PC >> 14)) & (SHIP_SIG_ENTRIES - 1));
}

// --- Initialization ---
void InitReplacementState() {
    memset(line_meta, 0, sizeof(line_meta));
    memset(stream_table, 0, sizeof(stream_table));
    memset(ship_outcome, 0, sizeof(ship_outcome));
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            line_meta[set][way].rrpv = RRPV_MAX;
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

    // Get PC signature
    uint8_t ship_sig = get_ship_sig(PC);

    // On fill (miss)
    if (!hit) {
        if (streaming) {
            // Streaming block: bypass (set RRPV to MAX so it is immediately evictable)
            line_meta[set][way].rrpv = RRPV_MAX;
            line_meta[set][way].ship_sig = ship_sig;
        } else {
            // SHiP outcome table guides insertion depth
            uint8_t outcome = ship_outcome[ship_sig];
            if (outcome >= 2) {
                // High reuse: insert at MRU
                line_meta[set][way].rrpv = 0;
            } else {
                // Low reuse: insert at distant
                line_meta[set][way].rrpv = RRPV_MAX;
            }
            line_meta[set][way].ship_sig = ship_sig;
        }
    } else {
        // On hit: promote to MRU and update SHiP outcome table
        line_meta[set][way].rrpv = 0;
        ship_outcome[line_meta[set][way].ship_sig] = std::min((uint8_t)3, ship_outcome[line_meta[set][way].ship_sig] + 1);
    }

    // On eviction: decay SHiP outcome table for the evicted block
    if (!hit && victim_addr != 0) {
        // Find victim's PC signature (if possible)
        uint8_t victim_sig = line_meta[set][way].ship_sig;
        ship_outcome[victim_sig] = (ship_outcome[victim_sig] > 0) ? ship_outcome[victim_sig] - 1 : 0;
    }
}

// --- Stats ---
void PrintStats() {
    std::cout << "SLSB Policy: SHiP-Lite with Streaming Bypass" << std::endl;
    // Print SHiP outcome table summary
    int high_reuse = 0, low_reuse = 0;
    for (int i = 0; i < SHIP_SIG_ENTRIES; ++i) {
        if (ship_outcome[i] >= 2) high_reuse++;
        else low_reuse++;
    }
    std::cout << "SHiP outcome table: " << high_reuse << " high-reuse, " << low_reuse << " low-reuse entries" << std::endl;
}
void PrintStats_Heartbeat() {}