#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- Parameters ---
#define SHIP_SIG_BITS 12 // 4K entries
#define SHIP_SIG_MASK ((1 << SHIP_SIG_BITS) - 1)
#define SHIP_COUNTER_BITS 2 // 2-bit outcome counter
#define STREAM_DETECT_LEN 4 // 4 consecutive deltas
#define STREAM_DELTA_BITS 16 // track lower 16 bits of delta

// --- Metadata structures ---
struct SHIPEntry {
    uint8_t counter; // 2 bits
};

struct StreamDetector {
    uint16_t last_addr_low;
    uint16_t last_delta;
    uint8_t streak;
};

struct LineMeta {
    uint8_t rrpv; // 2 bits
    uint8_t reuse; // 1 bit: dead-block approximation
};

// --- Global state ---
SHIPEntry ship_table[1 << SHIP_SIG_BITS];
StreamDetector stream_table[LLC_SETS];
LineMeta line_meta[LLC_SETS][LLC_WAYS];

// --- Helper functions ---
inline uint32_t get_ship_sig(uint64_t PC) {
    // Use lower bits of PC for signature
    return (PC >> 2) & SHIP_SIG_MASK;
}

// --- Initialization ---
void InitReplacementState() {
    memset(ship_table, 0, sizeof(ship_table));
    memset(stream_table, 0, sizeof(stream_table));
    memset(line_meta, 0, sizeof(line_meta));
    // Set all RRPVs to max (3)
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            line_meta[set][way].rrpv = 3;
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

// --- Victim selection: SRRIP with dead-block protection ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Prefer blocks with RRPV==3 and reuse==0
    for (uint32_t rrpv = 3; rrpv >= 0; --rrpv) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (line_meta[set][way].rrpv == rrpv && line_meta[set][way].reuse == 0)
                return way;
        }
    }
    // If all blocks are reused, fall back to RRPV==3
    for (uint32_t way = 0; way < LLC_WAYS; ++way) {
        if (line_meta[set][way].rrpv == 3)
            return way;
    }
    // Otherwise, evict way 0
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
    uint32_t sig = get_ship_sig(PC);

    // Streaming detection
    bool streaming = is_streaming(set, paddr);

    // On fill (miss)
    if (!hit) {
        // Streaming block: bypass (insert with RRPV=3)
        if (streaming) {
            line_meta[set][way].rrpv = 3;
            line_meta[set][way].reuse = 0;
        } else {
            // Use SHiP outcome counter to bias insertion
            uint8_t ctr = ship_table[sig].counter;
            if (ctr >= 2) {
                line_meta[set][way].rrpv = 0; // hot PC: MRU
            } else if (ctr == 1) {
                line_meta[set][way].rrpv = 2; // warm PC: mid
            } else {
                line_meta[set][way].rrpv = 3; // cold PC: distant
            }
            line_meta[set][way].reuse = 0;
        }
    } else {
        // On hit: promote to MRU, mark as reused
        line_meta[set][way].rrpv = 0;
        line_meta[set][way].reuse = 1;
        // Update SHiP outcome counter (max 3)
        if (ship_table[sig].counter < 3)
            ship_table[sig].counter++;
    }

    // On eviction: decay SHiP counter if block was dead
    if (!hit) {
        uint32_t victim_sig = get_ship_sig(PC);
        if (line_meta[set][way].reuse == 0 && ship_table[victim_sig].counter > 0)
            ship_table[victim_sig].counter--;
    }

    // Periodically decay reuse flags (approximate dead-blocks)
    static uint64_t access_count = 0;
    access_count++;
    if ((access_count & 0xFFF) == 0) { // every 4096 accesses
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            for (uint32_t w = 0; w < LLC_WAYS; ++w)
                line_meta[s][w].reuse = 0;
    }
}

// --- Stats ---
void PrintStats() {
    std::cout << "HSRS Policy: Hybrid Signature-Recency Streaming" << std::endl;
}
void PrintStats_Heartbeat() {}