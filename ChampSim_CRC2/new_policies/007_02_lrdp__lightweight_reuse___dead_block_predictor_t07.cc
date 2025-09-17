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
#define SHIP_TABLE_SIZE 2048
#define SHIP_CTR_BITS 2 // 2 bits/counter

// --- RRIP parameters ---
#define RRPV_BITS 2
#define RRPV_MAX ((1 << RRPV_BITS) - 1)
#define SRRIP_INSERT 1

// --- Dead-block counter ---
#define DEADCTR_BITS 2
#define DEADCTR_MAX ((1 << DEADCTR_BITS) - 1)
#define DECAY_INTERVAL 8192 // Periodic decay of live counters

// --- Streaming detector ---
#define STREAM_DETECT_LEN 3 // streak length

struct LineMeta {
    uint8_t rrpv;      // 2 bits
    uint8_t signature; // 6 bits
    uint8_t deadctr;   // 2 bits
};

struct StreamDetector {
    uint32_t last_addr_low;
    uint32_t last_delta;
    uint8_t streak;
    bool streaming;
};

uint8_t ship_table[SHIP_TABLE_SIZE];
StreamDetector stream_table[LLC_SETS];
LineMeta line_meta[LLC_SETS][LLC_WAYS];

// Periodic decay counter
uint64_t global_fill_count = 0;

// Helper: extract SHiP signature (6 bits from PC)
inline uint8_t get_signature(uint64_t PC) {
    return (uint8_t)((PC >> 2) ^ (PC >> 7)) & ((1<<SHIP_SIG_BITS)-1);
}

void InitReplacementState() {
    memset(line_meta, 0, sizeof(line_meta));
    memset(stream_table, 0, sizeof(stream_table));
    memset(ship_table, 0, sizeof(ship_table));
    global_fill_count = 0;
    // Initialize all lines as "dead"
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            line_meta[set][way].rrpv = RRPV_MAX;
            line_meta[set][way].signature = 0;
            line_meta[set][way].deadctr = 0;
        }
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        stream_table[set].streaming = false;
}

// Streaming detector: detects monotonic stride pattern
bool update_streaming(uint32_t set, uint64_t paddr) {
    StreamDetector &sd = stream_table[set];
    uint32_t addr_low = paddr & 0xFFFFF;
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

// Find victim: prefer dead blocks first; otherwise classic SRRIP
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // First, search for a block predicted dead (deadctr==0)
    for (uint32_t way = 0; way < LLC_WAYS; ++way) {
        if (line_meta[set][way].deadctr == 0)
            return way;
    }
    // If none, pick block with RRPV==MAX
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
    global_fill_count++;

    // Streaming detector
    bool streaming = update_streaming(set, paddr);

    // Get PC signature
    uint8_t sig = get_signature(PC);

    // On fill (miss)
    if (!hit) {
        uint8_t ship_ctr = ship_table[sig];

        // If streaming region, bypass (do not fill)
        if (streaming) {
            line_meta[set][way].rrpv = RRPV_MAX;
            line_meta[set][way].deadctr = 0;
        }
        // If SHiP predicts high reuse OR deadctr indicates live, insert at MRU
        else if (ship_ctr == 3 || line_meta[set][way].deadctr > 0) {
            line_meta[set][way].rrpv = 0;
            line_meta[set][way].deadctr = DEADCTR_MAX;
        }
        // Otherwise insert at distant RRPV, mark dead
        else {
            line_meta[set][way].rrpv = RRPV_MAX;
            line_meta[set][way].deadctr = 0;
        }
        // Set signature
        line_meta[set][way].signature = sig;
    } else {
        // On hit: promote to MRU and increment deadctr
        line_meta[set][way].rrpv = 0;
        if (line_meta[set][way].deadctr < DEADCTR_MAX)
            line_meta[set][way].deadctr++;
    }

    // SHiP training: on eviction, update SHiP table
    // If block was not reused, decrement SHiP counter
    // If reused, increment
    if (!hit) {
        uint8_t evict_sig = line_meta[set][way].signature;
        if (evict_sig < SHIP_TABLE_SIZE && ship_table[evict_sig] > 0)
            ship_table[evict_sig]--;
    } else {
        uint8_t sig = line_meta[set][way].signature;
        if (sig < SHIP_TABLE_SIZE && ship_table[sig] < 3)
            ship_table[sig]++;
    }

    // Periodic decay of dead-block counters
    if ((global_fill_count & (DECAY_INTERVAL - 1)) == 0) {
        for (uint32_t set = 0; set < LLC_SETS; ++set) {
            for (uint32_t way = 0; way < LLC_WAYS; ++way) {
                if (line_meta[set][way].deadctr > 0)
                    line_meta[set][way].deadctr--;
            }
        }
    }
}

void PrintStats() {
    std::cout << "LRDP Policy: Lightweight Reuse & Dead-block Predictor" << std::endl;
    uint64_t total_fills = 0, dead_inserts = 0, mrufills = 0, streaming_bypass = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            total_fills++;
            if (line_meta[set][way].deadctr == 0)
                dead_inserts++;
            if (line_meta[set][way].rrpv == 0)
                mrufills++;
            if (stream_table[set].streaming && line_meta[set][way].rrpv == RRPV_MAX)
                streaming_bypass++;
        }
    }
    std::cout << "Fraction dead-block distant-inserts: " << (double)dead_inserts / total_fills << std::endl;
    std::cout << "Fraction MRU-inserts (live/reuse-predicted): " << (double)mrufills / total_fills << std::endl;
    std::cout << "Streaming bypasses: " << streaming_bypass << std::endl;
}
void PrintStats_Heartbeat() {}