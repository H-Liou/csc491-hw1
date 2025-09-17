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
#define DISTANT_INSERT 3 // For streaming/dead blocks
#define LIP_INSERT RRPV_MAX // For LIP: always at LRU

#define PSEL_BITS 10
#define PSEL_MAX ((1 << PSEL_BITS) - 1)
#define PSEL_INIT (PSEL_MAX / 2)
#define NUM_LEADER_SETS 32
#define SRRIP_LEADER_SET_INTERVAL 64
#define LIP_LEADER_SET_INTERVAL 64

// --- Streaming detector ---
#define STREAM_DETECT_LEN 3 // streak for streaming

// Per-line metadata
struct LineMeta {
    uint8_t rrpv;      // 2 bits
    uint8_t signature; // 6 bits
};

// Streaming detector: stores last addr, delta, streak, and streaming flag
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

// Set-dueling leader sets
bool is_srrip_leader[LLC_SETS];
bool is_lip_leader[LLC_SETS];

// PSEL for SRRIP/LIP
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
    memset(is_lip_leader, 0, sizeof(is_lip_leader));
    psel = PSEL_INIT;

    // Assign leader sets for SRRIP and LIP
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i) {
        is_srrip_leader[i * SRRIP_LEADER_SET_INTERVAL] = true;
        is_lip_leader[i * LIP_LEADER_SET_INTERVAL + 32] = true;
    }
    // Initialize per-line metadata
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            line_meta[set][way].rrpv = RRPV_MAX;
            line_meta[set][way].signature = 0;
        }
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        stream_table[set].streaming = false;
}

// Streaming detector: detects monotonic stride pattern
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

// Victim selection: standard SRRIP
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

    // Set-dueling: choose insertion policy
    bool use_srrip;
    if (is_srrip_leader[set])
        use_srrip = true;
    else if (is_lip_leader[set])
        use_srrip = false;
    else
        use_srrip = (psel >= PSEL_INIT);

    // On fill (miss)
    if (!hit) {
        uint8_t ship_ctr = ship_table[sig];

        // Streaming detected or dead-block: insert at distant RRPV
        if (streaming || ship_ctr == 0) {
            line_meta[set][way].rrpv = DISTANT_INSERT;
        }
        // Otherwise: use LIP or SRRIP policy
        else {
            if (use_srrip)
                line_meta[set][way].rrpv = 2; // SRRIP default insert
            else
                line_meta[set][way].rrpv = LIP_INSERT; // LIP: always at LRU
        }
        // Set metadata
        line_meta[set][way].signature = sig;
    } else {
        // On hit: promote to MRU
        line_meta[set][way].rrpv = 0;
    }

    // SHiP training: on eviction, update SHiP table
    // If block was not reused (hit==0), decrement SHiP counter for its signature
    // If reused (hit==1), increment
    if (!hit) {
        uint8_t evict_sig = line_meta[set][way].signature;
        if (evict_sig < SHIP_TABLE_SIZE && ship_table[evict_sig] > 0)
            ship_table[evict_sig]--;
    } else {
        uint8_t sig = line_meta[set][way].signature;
        if (sig < SHIP_TABLE_SIZE && ship_table[sig] < 3)
            ship_table[sig]++;
    }

    // Set-dueling PSEL update
    if (is_srrip_leader[set]) {
        if (hit && psel < PSEL_MAX) psel++;
        else if (!hit && psel > 0) psel--;
    } else if (is_lip_leader[set]) {
        if (hit && psel > 0) psel--;
        else if (!hit && psel < PSEL_MAX) psel++;
    }
}

// --- Statistics ---
void PrintStats() {
    std::cout << "SHIP-LIP-SDI Policy: SHiP-LIP Hybrid with Streaming-aware Distant Insert" << std::endl;
    uint64_t total_fills = 0, distant_inserts = 0, lip_inserts = 0, srrip_inserts = 0, mrupromotes = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            total_fills++;
            if (line_meta[set][way].rrpv == DISTANT_INSERT)
                distant_inserts++;
            if (line_meta[set][way].rrpv == LIP_INSERT)
                lip_inserts++;
            if (line_meta[set][way].rrpv == 2)
                srrip_inserts++;
            if (line_meta[set][way].rrpv == 0)
                mrupromotes++;
        }
    }
    std::cout << "Fraction distant inserts (streaming/dead): "
              << (double)distant_inserts / total_fills << std::endl;
    std::cout << "Fraction LIP inserts: "
              << (double)lip_inserts / total_fills << std::endl;
    std::cout << "Fraction SRRIP inserts: "
              << (double)srrip_inserts / total_fills << std::endl;
    std::cout << "Fraction MRU promotions: "
              << (double)mrupromotes / total_fills << std::endl;
    std::cout << "PSEL value: " << psel << "/" << PSEL_MAX << std::endl;
}
void PrintStats_Heartbeat() {}