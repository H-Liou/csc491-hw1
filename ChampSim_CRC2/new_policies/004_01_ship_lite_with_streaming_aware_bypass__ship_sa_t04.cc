#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- SHiP-lite parameters ---
#define SIG_BITS 6
#define SIG_MASK ((1 << SIG_BITS) - 1)
#define SHIP_TABLE_SIZE 4096 // 2^12 entries
#define SHIP_CTR_BITS 2
#define SHIP_CTR_MAX ((1 << SHIP_CTR_BITS) - 1)

// --- Streaming detector parameters ---
#define STREAM_DETECT_LEN 4

// --- Metadata structures ---
struct LineMeta {
    uint8_t rrpv;         // 2 bits
    uint8_t pc_sig;       // 6 bits
};

struct StreamDetector {
    uint32_t last_addr_low;
    uint32_t last_delta;
    uint8_t streak;
};

// --- Global state ---
LineMeta line_meta[LLC_SETS][LLC_WAYS];
StreamDetector stream_table[LLC_SETS];

// SHiP outcome table: 4096 entries, 2 bits each
uint8_t ship_table[SHIP_TABLE_SIZE];

// Helper: extract 6-bit PC signature
inline uint8_t get_pc_sig(uint64_t PC) {
    // Use CRC to mix bits, then mask
    return (champsim_crc2(PC) & SIG_MASK);
}

// Helper: index into SHiP table
inline uint32_t ship_index(uint8_t pc_sig) {
    // Direct mapping for simplicity
    return pc_sig;
}

// --- Initialization ---
void InitReplacementState() {
    memset(line_meta, 0, sizeof(line_meta));
    memset(stream_table, 0, sizeof(stream_table));
    memset(ship_table, SHIP_CTR_MAX / 2, sizeof(ship_table)); // neutral start

    // Initialize RRPV and PC signature
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            line_meta[set][way].rrpv = 3; // RRPV_MAX
            line_meta[set][way].pc_sig = 0;
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
            if (line_meta[set][way].rrpv == 3)
                return way;
        }
        // Increment all RRPVs
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (line_meta[set][way].rrpv < 3)
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
    uint8_t pc_sig = get_pc_sig(PC);
    uint32_t ship_idx = ship_index(pc_sig);

    bool streaming = is_streaming(set, paddr);

    // On fill (miss)
    if (!hit) {
        // Streaming: insert with distant RRPV (bypass)
        if (streaming) {
            line_meta[set][way].rrpv = 3;
        } else {
            // Use SHiP outcome counter to select insertion depth
            uint8_t ctr = ship_table[ship_idx];
            if (ctr >= (SHIP_CTR_MAX / 2))
                line_meta[set][way].rrpv = 1; // Favor MRU insertion for "good" PCs
            else
                line_meta[set][way].rrpv = 3; // Favor LRU insertion for "dead" PCs
        }
        // Store PC signature in line metadata
        line_meta[set][way].pc_sig = pc_sig;
    } else {
        // On hit: promote to MRU
        line_meta[set][way].rrpv = 0;

        // Update SHiP outcome counter for PC
        uint8_t old_sig = line_meta[set][way].pc_sig;
        uint32_t old_idx = ship_index(old_sig);
        if (ship_table[old_idx] < SHIP_CTR_MAX)
            ship_table[old_idx]++;
    }

    // On eviction: decay SHiP outcome counter if block was not reused
    if (!hit) {
        uint8_t old_sig = line_meta[set][way].pc_sig;
        uint32_t old_idx = ship_index(old_sig);
        if (ship_table[old_idx] > 0)
            ship_table[old_idx]--;
    }
}

// --- Stats ---
void PrintStats() {
    std::cout << "SHiP-SA Policy: SHiP-lite with Streaming-Aware Bypass" << std::endl;
    // Print SHiP table reuse distribution
    uint32_t good = 0, dead = 0;
    for (uint32_t i = 0; i < SHIP_TABLE_SIZE; ++i) {
        if (ship_table[i] >= (SHIP_CTR_MAX / 2)) good++;
        else dead++;
    }
    std::cout << "SHiP table: " << good << " good PCs, " << dead << " dead PCs" << std::endl;
}

void PrintStats_Heartbeat() {}