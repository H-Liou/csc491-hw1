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
#define NUM_LEADER_SETS 64

// --- Streaming detector ---
#define STREAM_DETECT_LEN 4

struct LineMeta {
    uint8_t rrpv; // 2 bits
};

struct StreamDetector {
    uint32_t last_addr_low;
    uint32_t last_delta;
    uint8_t streak;
    bool streaming;
};

// Per-line metadata
LineMeta line_meta[LLC_SETS][LLC_WAYS];

// DRRIP PSEL counter
uint16_t psel = PSEL_MAX / 2;

// Leader set mapping
uint8_t leader_set_type[LLC_SETS]; // 0: SRRIP, 1: BRRIP

// Streaming detector per set
StreamDetector stream_table[LLC_SETS];

// --- Initialization ---
void InitReplacementState() {
    memset(line_meta, 0, sizeof(line_meta));
    memset(stream_table, 0, sizeof(stream_table));
    // Assign leader sets: alternate SRRIP/BRRIP for first NUM_LEADER_SETS sets
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        if (set < NUM_LEADER_SETS / 2)
            leader_set_type[set] = 0; // SRRIP leader
        else if (set < NUM_LEADER_SETS)
            leader_set_type[set] = 1; // BRRIP leader
        else
            leader_set_type[set] = 2; // follower
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            line_meta[set][way].rrpv = RRPV_MAX;
    }
    psel = PSEL_MAX / 2;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        stream_table[set].streaming = false;
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
    // Streaming detection
    bool streaming = update_streaming(set, paddr);

    // On fill (miss)
    if (!hit) {
        // Streaming-triggered bypass: if streaming detected, do not insert (set RRPV=MAX)
        if (streaming) {
            line_meta[set][way].rrpv = RRPV_MAX;
            return;
        }

        // DRRIP insertion policy
        uint8_t ins_rrpv = RRPV_MAX; // default LRU
        if (leader_set_type[set] == 0) { // SRRIP leader
            ins_rrpv = 2; // SRRIP: insert at RRPV=2
        } else if (leader_set_type[set] == 1) { // BRRIP leader
            ins_rrpv = (rand() % 32 == 0) ? 2 : RRPV_MAX; // BRRIP: insert at RRPV=2 with low probability
        } else { // follower sets
            if (psel >= (PSEL_MAX / 2))
                ins_rrpv = 2; // SRRIP
            else
                ins_rrpv = (rand() % 32 == 0) ? 2 : RRPV_MAX; // BRRIP
        }
        line_meta[set][way].rrpv = ins_rrpv;
    } else {
        // On hit: promote to MRU
        line_meta[set][way].rrpv = 0;
    }

    // DRRIP PSEL update: only for leader sets
    if (!hit) {
        if (leader_set_type[set] == 0) { // SRRIP leader
            if (line_meta[set][way].rrpv == RRPV_MAX && psel < PSEL_MAX)
                psel++;
        } else if (leader_set_type[set] == 1) { // BRRIP leader
            if (line_meta[set][way].rrpv == RRPV_MAX && psel > 0)
                psel--;
        }
    }
}

// --- Stats ---
void PrintStats() {
    std::cout << "DRRIP-LIP-STB Policy: DRRIP-LIP Hybrid with Streaming-Triggered Bypass" << std::endl;
    uint64_t streaming_sets = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        if (stream_table[set].streaming) streaming_sets++;
    std::cout << "Streaming sets: " << streaming_sets << "/" << LLC_SETS << std::endl;
    std::cout << "Final PSEL value: " << psel << " (max " << PSEL_MAX << ")" << std::endl;
}

void PrintStats_Heartbeat() {}