#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- SHiP parameters ---
#define SHIP_SIG_BITS 6            // 6-bit signature
#define SHIP_TABLE_SIZE 2048       // 2K-entry table
#define SHIP_CTR_BITS 2            // 2-bit outcome counter

// --- Dead-block tracking ---
#define DEADCTR_BITS 8
#define DEADCTR_MAX ((1<<DEADCTR_BITS)-1)
#define DEADCTR_INIT 2             // Slight reuse bias
#define DEADCTR_DECAY_INTERVAL 4096

// --- RRPV ---
#define RRPV_BITS 2
#define RRPV_MAX ((1 << RRPV_BITS) - 1)

// --- Streaming detector ---
#define STREAM_DETECT_LEN 4

// --- Metadata structures ---
struct LineMeta {
    uint8_t rrpv;              // 2 bits
    uint8_t deadctr;           // 8 bits
    uint8_t signature;         // 6 bits
};

struct StreamDetector {
    uint32_t last_addr_low;
    uint32_t last_delta;
    uint8_t streak;
    bool streaming;
};

// SHiP table: index by signature, 2 bits per entry
uint8_t ship_table[SHIP_TABLE_SIZE];

// Per-set streaming detector
StreamDetector stream_table[LLC_SETS];

// Per-line metadata
LineMeta line_meta[LLC_SETS][LLC_WAYS];

// Dead-block decay counter (global)
uint32_t deadctr_decay_counter = 0;

// Helper: extract SHiP signature (6 bits from PC)
inline uint8_t get_signature(uint64_t PC) {
    return (uint8_t)((PC >> 2) ^ (PC >> 7)) & ((1<<SHIP_SIG_BITS)-1);
}

// --- Initialization ---
void InitReplacementState() {
    memset(line_meta, 0, sizeof(line_meta));
    memset(stream_table, 0, sizeof(stream_table));
    memset(ship_table, 0, sizeof(ship_table));
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            line_meta[set][way].rrpv = RRPV_MAX;
            line_meta[set][way].deadctr = DEADCTR_INIT;
            line_meta[set][way].signature = 0;
        }
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        stream_table[set].streaming = false;
    deadctr_decay_counter = 0;
}

// --- Streaming detector ---
bool update_streaming(uint32_t set, uint64_t paddr) {
    StreamDetector &sd = stream_table[set];
    uint32_t addr_low = paddr & 0xFFFFF; // lower ~1MB window
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
    sd.streaming = streaming;
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
    // Dead-block decay
    deadctr_decay_counter++;
    if (deadctr_decay_counter % DEADCTR_DECAY_INTERVAL == 0) {
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            for (uint32_t w = 0; w < LLC_WAYS; ++w)
                if (line_meta[s][w].deadctr > 0)
                    line_meta[s][w].deadctr--;
    }

    // Streaming detection
    bool streaming = update_streaming(set, paddr);

    // Get PC signature
    uint8_t sig = get_signature(PC);

    // On fill (miss)
    if (!hit) {
        // If streaming and deadctr is low: bypass (do not insert)
        if (streaming && line_meta[set][way].deadctr <= 1) {
            line_meta[set][way].rrpv = RRPV_MAX; // immediate eviction (bypass)
            line_meta[set][way].signature = sig;
            line_meta[set][way].deadctr = DEADCTR_INIT;
            // No update to SHiP table, dead blocks are not tracked
            return;
        }

        // SHiP insertion: if PC signature shows reuse (counter >=2), insert at RRPV=0 (MRU)
        // Otherwise, insert at RRPV=RRPV_MAX (LRU), moderate at 1
        uint8_t ctr = ship_table[sig];
        if (ctr >= 2)
            line_meta[set][way].rrpv = 0;     // MRU insertion
        else if (ctr == 1)
            line_meta[set][way].rrpv = 1;     // moderate
        else
            line_meta[set][way].rrpv = RRPV_MAX; // LRU insertion

        // Set metadata
        line_meta[set][way].signature = sig;
        line_meta[set][way].deadctr = DEADCTR_INIT;
    } else {
        // On hit: promote to MRU
        line_meta[set][way].rrpv = 0;
        // Deadctr up to max
        if (line_meta[set][way].deadctr < DEADCTR_MAX)
            line_meta[set][way].deadctr++;
    }

    // SHiP training: on eviction, update SHiP table
    // If a block was not reused (deadctr <= 1), decrement SHiP counter for its signature
    // If it was reused (deadctr > 1), increment
    if (!hit) {
        uint8_t evict_sig = line_meta[set][way].signature;
        uint8_t evict_dead = line_meta[set][way].deadctr;
        if (evict_sig < SHIP_TABLE_SIZE) {
            if (evict_dead <= 1 && ship_table[evict_sig] > 0)
                ship_table[evict_sig]--;
            else if (evict_dead > 1 && ship_table[evict_sig] < 3)
                ship_table[evict_sig]++;
        }
    }
}

// --- Stats ---
void PrintStats() {
    std::cout << "SHiP-SA-DBB Policy: SHiP-Lite with Streaming-Aware Dead-Block Bypass" << std::endl;
    // Count blocks bypassed due to streaming + dead-block
    uint64_t total_fills = 0, bypassed = 0, streaming_sets = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        if (stream_table[set].streaming) streaming_sets++;
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            total_fills++;
            if (line_meta[set][way].rrpv == RRPV_MAX && stream_table[set].streaming && line_meta[set][way].deadctr <= 1)
                bypassed++;
        }
    }
    std::cout << "Streaming sets: " << streaming_sets << "/" << LLC_SETS << std::endl;
    std::cout << "Approx fraction of streaming-bypassed lines: "
              << (double)bypassed / total_fills << std::endl;
}
void PrintStats_Heartbeat() {}