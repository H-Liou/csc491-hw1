#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- SHiP-lite parameters ---
#define SIG_BITS 5           // PC signature bits per line
#define OUTCOME_BITS 2       // 2-bit outcome counter per line
#define RRPV_BITS 2
#define RRPV_MAX ((1 << RRPV_BITS) - 1)

// --- Streaming detector parameters ---
#define STREAM_DETECT_LEN 4
#define STREAM_DELTA_BITS 16

// --- Metadata structures ---
struct LineMeta {
    uint8_t rrpv;             // 2 bits
    uint8_t outcome;          // 2 bits
    uint8_t pc_sig;           // 5 bits
};

struct StreamDetector {
    uint16_t last_addr_low;
    uint16_t last_delta;
    uint8_t streak;
};

// --- Global state ---
LineMeta line_meta[LLC_SETS][LLC_WAYS];
StreamDetector stream_table[LLC_SETS];

// --- Helper functions ---
static inline uint8_t pc_sig_hash(uint64_t PC) {
    // Simple hash: XOR and mask to 5 bits
    return (uint8_t)((PC ^ (PC >> 7) ^ (PC >> 13)) & ((1 << SIG_BITS) - 1));
}

// --- Initialization ---
void InitReplacementState() {
    memset(line_meta, 0, sizeof(line_meta));
    memset(stream_table, 0, sizeof(stream_table));
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            line_meta[set][way].rrpv = RRPV_MAX;
            line_meta[set][way].outcome = 1; // neutral start
            line_meta[set][way].pc_sig = 0;
        }
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

    // --- SHiP-lite: compute PC signature ---
    uint8_t sig = pc_sig_hash(PC);

    // On fill (miss)
    if (!hit) {
        if (streaming) {
            // Streaming block: bypass (set RRPV to MAX so it is immediately evictable)
            line_meta[set][way].rrpv = RRPV_MAX;
        } else {
            // SHiP-lite: insertion depth based on outcome counter
            if (line_meta[set][way].outcome >= 2) {
                // Insert at MRU (reuse predicted)
                line_meta[set][way].rrpv = 0;
            } else {
                // Insert at distant (reuse not predicted)
                line_meta[set][way].rrpv = RRPV_MAX;
            }
            // Save PC signature
            line_meta[set][way].pc_sig = sig;
        }
    } else {
        // On hit: promote to MRU
        line_meta[set][way].rrpv = 0;
        // Update outcome counter (saturate at max)
        if (line_meta[set][way].outcome < 3)
            line_meta[set][way].outcome++;
    }

    // On eviction, decay outcome counter
    // (approximate dead-block: if a block is evicted without reuse, penalize its PC signature)
    if (!hit && victim_addr != 0) {
        // Find victim way by address
        for (uint32_t vway = 0; vway < LLC_WAYS; ++vway) {
            // Champsim: current_set[vway].address == victim_addr
            // If you have access to current_set, you can match victim_addr
            // Here, we just decay all lines in set (conservative)
            if (line_meta[set][vway].outcome > 0)
                line_meta[set][vway].outcome--;
        }
    }
}

// --- Stats ---
void PrintStats() {
    std::cout << "SLSB Policy: SHiP-Lite with Streaming Bypass" << std::endl;
    // Optionally print outcome counter histogram
    uint64_t total_lines = 0, reused_lines = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            total_lines++;
            if (line_meta[set][way].outcome >= 2)
                reused_lines++;
        }
    std::cout << "Fraction of lines predicted reusable: "
              << (double)reused_lines / total_lines << std::endl;
}
void PrintStats_Heartbeat() {}