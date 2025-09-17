#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- DIP parameters ---
#define DIP_LEADER_SETS 64
#define DIP_LEADER_MASK (DIP_LEADER_SETS - 1)
#define DIP_PSEL_MAX 1023 // 10-bit PSEL

// --- Streaming detector ---
#define STREAM_DETECT_LEN 4
#define STREAM_DELTA_BITS 16

// --- Metadata structures ---
struct StreamDetector {
    uint16_t last_addr_low;
    uint16_t last_delta;
    uint8_t streak;
};

struct LineMeta {
    uint8_t rrpv;   // 2 bits
    uint8_t reuse;  // 1 bit
};

// --- Global state ---
StreamDetector stream_table[LLC_SETS];
LineMeta line_meta[LLC_SETS][LLC_WAYS];

// DIP set-dueling
uint16_t dip_psel = DIP_PSEL_MAX / 2; // 10-bit counter
// Leader sets: first 32 for LIP, next 32 for BIP
bool is_lip_leader(uint32_t set) { return (set & DIP_LEADER_MASK) < (DIP_LEADER_SETS / 2); }
bool is_bip_leader(uint32_t set) { return (set & DIP_LEADER_MASK) >= (DIP_LEADER_SETS / 2); }

// --- Initialization ---
void InitReplacementState() {
    memset(stream_table, 0, sizeof(stream_table));
    memset(line_meta, 0, sizeof(line_meta));
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            line_meta[set][way].rrpv = 3;
    dip_psel = DIP_PSEL_MAX / 2;
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
    // Streaming detection
    bool streaming = is_streaming(set, paddr);

    // DIP insertion policy selection
    bool use_lip = false;
    if (is_lip_leader(set)) use_lip = true;
    else if (is_bip_leader(set)) use_lip = false;
    else use_lip = (dip_psel < (DIP_PSEL_MAX / 2)); // follower sets

    // On fill (miss)
    if (!hit) {
        if (streaming) {
            // Streaming block: bypass (insert with RRPV=3)
            line_meta[set][way].rrpv = 3;
            line_meta[set][way].reuse = 0;
        } else {
            // DIP insertion depth
            if (use_lip) {
                line_meta[set][way].rrpv = 3; // LRU insertion
            } else {
                // BIP: insert at MRU with low probability (1/32), else LRU
                static uint32_t bip_ctr = 0;
                bip_ctr++;
                if ((bip_ctr & 0x1F) == 0) // every 32 fills
                    line_meta[set][way].rrpv = 0;
                else
                    line_meta[set][way].rrpv = 3;
            }
            line_meta[set][way].reuse = 0;
        }
    } else {
        // On hit: promote to MRU, mark as reused
        line_meta[set][way].rrpv = 0;
        line_meta[set][way].reuse = 1;

        // DIP PSEL update for leader sets
        if (is_lip_leader(set) && !streaming) {
            if (dip_psel < DIP_PSEL_MAX) dip_psel++;
        }
        if (is_bip_leader(set) && !streaming) {
            if (dip_psel > 0) dip_psel--;
        }
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
    std::cout << "ADSH Policy: Adaptive DIP-Streaming Hybrid" << std::endl;
    std::cout << "Final DIP PSEL value: " << dip_psel << std::endl;
}
void PrintStats_Heartbeat() {}