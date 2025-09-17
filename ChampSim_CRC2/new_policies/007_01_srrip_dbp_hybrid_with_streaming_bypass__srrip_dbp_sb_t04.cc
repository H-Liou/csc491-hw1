#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- RRIP parameters ---
#define RRPV_BITS 2
#define RRPV_MAX ((1 << RRPV_BITS) - 1)
#define SRRIP_INSERT 1

// --- Dead-block predictor ---
#define DBP_BITS 2 // 2 bits per line
#define DBP_MAX 3
#define DBP_DECAY_INTERVAL 4096 // Decay every N fills

// --- Streaming detector ---
#define STREAM_DETECT_LEN 3 // streak length for streaming
struct StreamDetector {
    uint32_t last_addr_low;
    uint32_t last_delta;
    uint8_t streak;
    bool streaming;
};

// Per-line metadata
struct LineMeta {
    uint8_t rrpv;   // 2 bits
    uint8_t dbp;    // 2 bits: dead-block predictor
};

// Metadata arrays
LineMeta line_meta[LLC_SETS][LLC_WAYS];
StreamDetector stream_table[LLC_SETS];

// For periodic DBP decay
uint64_t global_fill_ctr = 0;

// Helper: Streaming detector
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

// Initialization
void InitReplacementState() {
    memset(line_meta, 0, sizeof(line_meta));
    memset(stream_table, 0, sizeof(stream_table));
    global_fill_ctr = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            line_meta[set][way].rrpv = RRPV_MAX;
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
    // Find block with RRPV==MAX
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (line_meta[set][way].rrpv == RRPV_MAX)
                return way;
        }
        // Increment all RRPVs (except already at max)
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
    // Streaming detection
    bool streaming = update_streaming(set, paddr);

    // On fill (miss)
    if (!hit) {
        global_fill_ctr++;

        // Streaming region: bypass fill (do not insert, mark as invalid)
        if (streaming) {
            // Mark as invalid by setting RRPV=max (will be chosen as victim immediately)
            line_meta[set][way].rrpv = RRPV_MAX;
            line_meta[set][way].dbp = 0;
            return;
        }

        // Dead-block predictor: insert at distant if predicted dead
        uint8_t dbp_ctr = line_meta[set][way].dbp;
        if (dbp_ctr == 0) {
            line_meta[set][way].rrpv = RRPV_MAX; // distant
        } else {
            line_meta[set][way].rrpv = SRRIP_INSERT; // default
        }
        // Reset DBP counter on fill
        line_meta[set][way].dbp = 0;

        // Periodic DBP decay: every DBP_DECAY_INTERVAL fills, halve all DBP counters
        if ((global_fill_ctr & (DBP_DECAY_INTERVAL-1)) == 0) {
            for (uint32_t s = 0; s < LLC_SETS; ++s)
                for (uint32_t w = 0; w < LLC_WAYS; ++w)
                    line_meta[s][w].dbp >>= 1;
        }
    } else {
        // On hit: promote to MRU, increment DBP counter
        line_meta[set][way].rrpv = 0;
        if (line_meta[set][way].dbp < DBP_MAX)
            line_meta[set][way].dbp++;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "SRRIP-DBP-SB Policy: SRRIP + Dead-block Predictor, Streaming Bypass" << std::endl;
    uint64_t total_fills = 0, streaming_bypass = 0, distant_inserts = 0, mrufills = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            total_fills++;
            if (stream_table[set].streaming && line_meta[set][way].rrpv == RRPV_MAX)
                streaming_bypass++;
            if (line_meta[set][way].rrpv == RRPV_MAX)
                distant_inserts++;
            if (line_meta[set][way].rrpv == 0)
                mrufills++;
        }
    }
    std::cout << "Fraction streaming-region bypasses: "
              << (double)streaming_bypass / total_fills << std::endl;
    std::cout << "Fraction distant-inserts (dead-block): "
              << (double)distant_inserts / total_fills << std::endl;
    std::cout << "Fraction MRU-inserts (hits): "
              << (double)mrufills / total_fills << std::endl;
}

void PrintStats_Heartbeat() {}