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
#define OUTCOME_BITS 2
#define OUTCOME_MAX ((1 << OUTCOME_BITS) - 1)

// --- RRIP parameters ---
#define RRPV_BITS 2
#define RRPV_MAX ((1 << RRPV_BITS) - 1)

// --- Streaming detector parameters ---
#define STREAM_DETECT_LEN 4

// --- Metadata structures ---
struct LineMeta {
    uint8_t rrpv;         // 2 bits
    uint8_t signature;    // 6 bits
    uint8_t outcome;      // 2 bits
};

struct StreamDetector {
    uint32_t last_addr_low;
    uint32_t last_delta;
    uint8_t streak;
};

// --- Global state ---
LineMeta line_meta[LLC_SETS][LLC_WAYS];
StreamDetector stream_table[LLC_SETS];

// --- Helper: get PC signature ---
inline uint8_t get_signature(uint64_t PC) {
    // Simple CRC hash, then mask to SIG_BITS
    return champsim_crc2(PC) & SIG_MASK;
}

// --- Initialization ---
void InitReplacementState() {
    memset(line_meta, 0, sizeof(line_meta));
    memset(stream_table, 0, sizeof(stream_table));
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            line_meta[set][way].rrpv = RRPV_MAX;
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
    uint8_t sig = get_signature(PC);
    bool streaming = is_streaming(set, paddr);

    // On fill (miss)
    if (!hit) {
        // Streaming: bypass (insert with RRPV MAX so evicted ASAP)
        if (streaming) {
            line_meta[set][way].rrpv = RRPV_MAX;
        } else {
            // Use SHiP outcome counter to bias insertion
            uint8_t outcome = line_meta[set][way].outcome;
            if (outcome >= OUTCOME_MAX / 2)
                line_meta[set][way].rrpv = 0; // MRU insertion for "hot" signature
            else
                line_meta[set][way].rrpv = RRPV_MAX; // LRU insertion for "cold"/dead signature
        }
        // Store signature
        line_meta[set][way].signature = sig;
        // Reset outcome counter on fill
        line_meta[set][way].outcome = 0;
    } else {
        // On hit: promote to MRU
        line_meta[set][way].rrpv = 0;
        // Update outcome counter for signature
        if (line_meta[set][way].outcome < OUTCOME_MAX)
            line_meta[set][way].outcome++;
    }
}

// --- Stats ---
void PrintStats() {
    std::cout << "SHiP-LSB Policy: SHiP-lite with Streaming Bypass" << std::endl;
    // Count fraction of blocks bypassed
    uint64_t total_lines = 0, streaming_lines = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            total_lines++;
            if (line_meta[set][way].rrpv == RRPV_MAX && line_meta[set][way].outcome == 0)
                streaming_lines++;
        }
    std::cout << "Approx fraction of streaming-bypassed lines: "
              << (double)streaming_lines / total_lines << std::endl;
}
void PrintStats_Heartbeat() {}