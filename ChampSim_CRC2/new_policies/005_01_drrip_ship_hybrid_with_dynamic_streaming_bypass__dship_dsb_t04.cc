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
#define SRRIP_INSERT 1
#define BRRIP_INSERT 2

#define PSEL_BITS 10
#define PSEL_MAX ((1 << PSEL_BITS) - 1)
#define PSEL_INIT (PSEL_MAX / 2)
#define NUM_LEADER_SETS 32
#define SRRIP_LEADER_SET_INTERVAL 64
#define BRRIP_LEADER_SET_INTERVAL 64

// --- SHiP-lite parameters ---
#define SHIP_SIG_BITS 6
#define SHIP_TABLE_SIZE 2048
#define SHIP_CTR_BITS 2

// --- Streaming detector ---
#define STREAM_DETECT_LEN 4

// --- Metadata structures ---
struct LineMeta {
    uint8_t rrpv;              // 2 bits
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

// DRRIP set-dueling: leader set assignment
bool is_srrip_leader[LLC_SETS];
bool is_brrip_leader[LLC_SETS];

// DRRIP PSEL counter
uint16_t psel;

// Helper: extract SHiP signature (6 bits from PC)
inline uint8_t get_signature(uint64_t PC) {
    return (uint8_t)((PC >> 2) ^ (PC >> 7)) & ((1<<SHIP_SIG_BITS)-1);
}

// --- Initialization ---
void InitReplacementState() {
    memset(line_meta, 0, sizeof(line_meta));
    memset(stream_table, 0, sizeof(stream_table));
    memset(ship_table, 0, sizeof(ship_table));
    memset(is_srrip_leader, 0, sizeof(is_srrip_leader));
    memset(is_brrip_leader, 0, sizeof(is_brrip_leader));
    psel = PSEL_INIT;

    // Assign leader sets
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i) {
        is_srrip_leader[i * SRRIP_LEADER_SET_INTERVAL] = true;
        is_brrip_leader[i * BRRIP_LEADER_SET_INTERVAL + 32] = true;
    }
    // Initialize metadata
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            line_meta[set][way].rrpv = RRPV_MAX;
            line_meta[set][way].signature = 0;
        }
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

    // Get PC signature
    uint8_t sig = get_signature(PC);

    // DRRIP set-dueling: determine insertion policy
    uint8_t ins_rrpv;
    if (is_srrip_leader[set]) {
        ins_rrpv = SRRIP_INSERT;
    } else if (is_brrip_leader[set]) {
        ins_rrpv = BRRIP_INSERT;
    } else {
        ins_rrpv = (psel >= PSEL_INIT) ? SRRIP_INSERT : BRRIP_INSERT;
    }

    // On fill (miss)
    if (!hit) {
        // Streaming bypass: If streaming and SHiP counter low, bypass (do not insert)
        uint8_t ship_ctr = ship_table[sig];
        if (streaming && ship_ctr == 0) {
            line_meta[set][way].rrpv = RRPV_MAX; // immediate eviction (bypass)
            line_meta[set][way].signature = sig;
            return;
        }

        // SHiP insertion: if PC signature shows high reuse (ctr==3), insert at MRU
        // Otherwise, use DRRIP's chosen insertion depth
        if (ship_ctr == 3)
            line_meta[set][way].rrpv = 0;     // MRU insertion
        else
            line_meta[set][way].rrpv = ins_rrpv;

        // Set metadata
        line_meta[set][way].signature = sig;
    } else {
        // On hit: promote to MRU
        line_meta[set][way].rrpv = 0;
    }

    // SHiP training: on eviction, update SHiP table
    // If a block was not reused (hit==0), decrement SHiP counter for its signature
    // If it was reused (hit==1), increment
    if (!hit) {
        uint8_t evict_sig = line_meta[set][way].signature;
        if (evict_sig < SHIP_TABLE_SIZE) {
            if (ship_table[evict_sig] > 0)
                ship_table[evict_sig]--;
        }
    } else {
        uint8_t sig = line_meta[set][way].signature;
        if (sig < SHIP_TABLE_SIZE && ship_table[sig] < 3)
            ship_table[sig]++;
    }

    // DRRIP set-dueling PSEL update
    if (is_srrip_leader[set]) {
        if (hit && psel < PSEL_MAX) psel++;
        else if (!hit && psel > 0) psel--;
    } else if (is_brrip_leader[set]) {
        if (hit && psel > 0) psel--;
        else if (!hit && psel < PSEL_MAX) psel++;
    }
}

// --- Stats ---
void PrintStats() {
    std::cout << "DSHIP-DSB Policy: DRRIP-SHiP Hybrid with Dynamic Streaming Bypass" << std::endl;
    // Count blocks bypassed due to streaming + SHiP
    uint64_t total_fills = 0, bypassed = 0, streaming_sets = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        if (stream_table[set].streaming) streaming_sets++;
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            total_fills++;
            uint8_t sig = line_meta[set][way].signature;
            if (line_meta[set][way].rrpv == RRPV_MAX && stream_table[set].streaming && sig < SHIP_TABLE_SIZE && ship_table[sig] == 0)
                bypassed++;
        }
    }
    std::cout << "Streaming sets: " << streaming_sets << "/" << LLC_SETS << std::endl;
    std::cout << "Approx fraction of streaming-bypassed lines: "
              << (double)bypassed / total_fills << std::endl;
    std::cout << "PSEL value: " << psel << "/" << PSEL_MAX << std::endl;
}
void PrintStats_Heartbeat() {}