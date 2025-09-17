#include <vector>
#include <cstdint>
#include <cstring>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- SHiP-lite: 5-bit PC signature, 2-bit reuse counter ---
#define SHIP_SIG_BITS 5
#define SHIP_SIG_ENTRIES (1 << SHIP_SIG_BITS)
#define SHIP_COUNTER_BITS 2

// --- Address-bit reuse predictor: 12 bits, 2-bit counter ---
#define ADDR_GROUP_BITS 12
#define ADDR_GROUP_ENTRIES (1 << ADDR_GROUP_BITS)
#define ADDR_COUNTER_BITS 2

// --- Streaming detector: per-set, last address, delta, 2-bit streaming counter ---
struct StreamingDetector {
    uint64_t last_addr;
    int64_t last_delta;
    uint8_t stream_count; // 2 bits
};

StreamingDetector streaming_detector[LLC_SETS];

// --- SHiP-lite table ---
struct SHIPEntry {
    uint8_t counter; // 2 bits
};
SHIPEntry ship_table[SHIP_SIG_ENTRIES];

// --- Address-bit reuse table ---
uint8_t addr_reuse_table[ADDR_GROUP_ENTRIES];

// --- Per-line RRPV ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// --- Helper: get SHiP signature ---
inline uint32_t get_ship_sig(uint64_t PC) {
    return (PC >> 2) & (SHIP_SIG_ENTRIES - 1);
}

// --- Helper: get address group ---
inline uint32_t get_addr_group(uint64_t paddr) {
    return (paddr >> 6) & (ADDR_GROUP_ENTRIES - 1); // block address
}

// --- Helper: streaming detector update ---
inline bool is_streaming(uint32_t set, uint64_t paddr) {
    StreamingDetector &sd = streaming_detector[set];
    int64_t delta = (int64_t)paddr - (int64_t)sd.last_addr;
    bool streaming = false;
    if (sd.last_addr != 0) {
        if (delta == sd.last_delta && delta != 0) {
            if (sd.stream_count < 3) sd.stream_count++;
        } else {
            if (sd.stream_count > 0) sd.stream_count--;
        }
        streaming = (sd.stream_count >= 2);
    }
    sd.last_delta = delta;
    sd.last_addr = paddr;
    return streaming;
}

// --- Initialization ---
void InitReplacementState() {
    memset(ship_table, 0, sizeof(ship_table));
    memset(addr_reuse_table, 0, sizeof(addr_reuse_table));
    memset(streaming_detector, 0, sizeof(streaming_detector));
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            rrpv[set][way] = 3; // distant
}

// --- Victim selection: choose block with max RRPV ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Streaming: bypass if detected
    if (is_streaming(set, paddr)) {
        // Find invalid block if possible
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (!current_set[way].valid)
                return way;
        // Otherwise, evict block with max RRPV
        uint32_t victim = 0;
        uint8_t max_rrpv = rrpv[set][0];
        for (uint32_t way = 1; way < LLC_WAYS; ++way) {
            if (rrpv[set][way] > max_rrpv) {
                max_rrpv = rrpv[set][way];
                victim = way;
            }
        }
        return victim;
    }

    // Normal: evict block with max RRPV
    uint32_t victim = 0;
    uint8_t max_rrpv = rrpv[set][0];
    for (uint32_t way = 1; way < LLC_WAYS; ++way) {
        if (rrpv[set][way] > max_rrpv) {
            max_rrpv = rrpv[set][way];
            victim = way;
        }
    }
    return victim;
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
    // Streaming detector update
    bool streaming = is_streaming(set, paddr);

    // SHiP signature and address group
    uint32_t sig = get_ship_sig(PC);
    uint32_t addr_grp = get_addr_group(paddr);

    // On hit: promote reuse counters
    if (hit) {
        if (ship_table[sig].counter < 3) ship_table[sig].counter++;
        if (addr_reuse_table[addr_grp] < 3) addr_reuse_table[addr_grp]++;
        rrpv[set][way] = 0; // MRU
        return;
    }

    // On fill (miss): set insertion depth
    if (streaming) {
        // Streaming: bypass (do not insert into cache)
        rrpv[set][way] = 3; // distant, will be evicted soon
        return;
    }

    // If strong SHiP reuse or address reuse, insert at MRU
    if (ship_table[sig].counter >= 2 || addr_reuse_table[addr_grp] >= 2) {
        rrpv[set][way] = 0; // MRU
    } else {
        rrpv[set][way] = 3; // distant
    }

    // On eviction: decay reuse counters for victim
    uint32_t victim_sig = get_ship_sig(PC);
    uint32_t victim_addr_grp = get_addr_group(victim_addr);
    if (ship_table[victim_sig].counter > 0) ship_table[victim_sig].counter--;
    if (addr_reuse_table[victim_addr_grp] > 0) addr_reuse_table[victim_addr_grp]--;
}

// --- Print end-of-simulation statistics ---
void PrintStats() {
    std::cout << "SASH Policy: SHiP-lite + Address Reuse + Streaming Detector" << std::endl;
}

// --- Print heartbeat statistics ---
void PrintStats_Heartbeat() {
    // Optional: print streaming detector stats
}