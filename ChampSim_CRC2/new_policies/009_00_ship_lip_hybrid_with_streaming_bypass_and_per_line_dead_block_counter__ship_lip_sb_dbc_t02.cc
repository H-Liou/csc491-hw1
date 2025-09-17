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
#define LIP_INSERT RRPV_MAX
#define BIP_INSERT 0

#define PSEL_BITS 10
#define PSEL_MAX ((1 << PSEL_BITS) - 1)
#define PSEL_INIT (PSEL_MAX / 2)
#define NUM_LEADER_SETS 32
#define LIP_LEADER_SET_INTERVAL 64
#define BIP_LEADER_SET_INTERVAL 64

// --- SHiP-lite parameters ---
#define SHIP_SIG_BITS 6
#define SHIP_TABLE_SIZE 2048
#define SHIP_CTR_BITS 2 // 2 bits/counter

// --- Streaming detector ---
#define STREAM_DETECT_LEN 3 // shorter streak: more sensitive

// --- Dead-block counter ---
#define DEAD_BLOCK_BITS 1 // 1 bit per line

// Per-line metadata
struct LineMeta {
    uint8_t rrpv;      // 2 bits
    uint8_t signature; // 6 bits
    uint8_t dead;      // 1 bit
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
bool is_lip_leader[LLC_SETS];
bool is_bip_leader[LLC_SETS];

// PSEL for LIP/BIP
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
    memset(is_lip_leader, 0, sizeof(is_lip_leader));
    memset(is_bip_leader, 0, sizeof(is_bip_leader));
    psel = PSEL_INIT;

    // Assign leader sets for LIP and BIP
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i) {
        is_lip_leader[i * LIP_LEADER_SET_INTERVAL] = true;
        is_bip_leader[i * BIP_LEADER_SET_INTERVAL + 32] = true;
    }
    // Initialize per-line metadata
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            line_meta[set][way].rrpv = RRPV_MAX;
            line_meta[set][way].signature = 0;
            line_meta[set][way].dead = 0;
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

// Victim selection: standard RRIP
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
    bool use_lip;
    if (is_lip_leader[set])
        use_lip = true;
    else if (is_bip_leader[set])
        use_lip = false;
    else
        use_lip = (psel >= PSEL_INIT);

    // On fill (miss)
    if (!hit) {
        uint8_t ship_ctr = ship_table[sig];

        // Streaming detected: bypass cache fill
        if (streaming) {
            // Do not fill the cache line; mark as dead
            line_meta[set][way].dead = 1;
            line_meta[set][way].rrpv = RRPV_MAX;
        }
        // SHiP high reuse: insert at MRU
        else if (ship_ctr == 3) {
            line_meta[set][way].rrpv = 0;
            line_meta[set][way].dead = 0;
        }
        // Dead-block approximation: if dead counter set, insert at LRU
        else if (line_meta[set][way].dead) {
            line_meta[set][way].rrpv = RRPV_MAX;
        }
        // Otherwise: LIP/BIP insertion
        else {
            if (use_lip)
                line_meta[set][way].rrpv = LIP_INSERT;
            else {
                // BIP: insert at MRU with 1/32 probability, else LRU
                if ((rand() % 32) == 0)
                    line_meta[set][way].rrpv = BIP_INSERT;
                else
                    line_meta[set][way].rrpv = LIP_INSERT;
            }
            line_meta[set][way].dead = 0;
        }

        // Set metadata
        line_meta[set][way].signature = sig;
    } else {
        // On hit: promote to MRU, clear dead counter
        line_meta[set][way].rrpv = 0;
        line_meta[set][way].dead = 0;
    }

    // SHiP training: on eviction, update SHiP table
    // If block was not reused (hit==0), decrement SHiP counter for its signature
    // If reused (hit==1), increment
    if (!hit) {
        uint8_t evict_sig = line_meta[set][way].signature;
        if (evict_sig < SHIP_TABLE_SIZE && ship_table[evict_sig] > 0)
            ship_table[evict_sig]--;
        // Dead-block approximation: increment dead counter
        line_meta[set][way].dead = 1;
    } else {
        uint8_t sig = line_meta[set][way].signature;
        if (sig < SHIP_TABLE_SIZE && ship_table[sig] < 3)
            ship_table[sig]++;
        // Clear dead counter on reuse
        line_meta[set][way].dead = 0;
    }

    // Set-dueling PSEL update
    if (is_lip_leader[set]) {
        if (hit && psel < PSEL_MAX) psel++;
        else if (!hit && psel > 0) psel--;
    } else if (is_bip_leader[set]) {
        if (hit && psel > 0) psel--;
        else if (!hit && psel < PSEL_MAX) psel++;
    }

    // Periodic dead-block decay (every 4096 fills)
    static uint64_t fill_count = 0;
    fill_count++;
    if ((fill_count & 0xFFF) == 0) {
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            for (uint32_t w = 0; w < LLC_WAYS; ++w)
                line_meta[s][w].dead = 0;
    }
}

// --- Statistics ---
void PrintStats() {
    std::cout << "SHiP-LIP-SB-DBC Policy: SHiP-LIP Hybrid with Streaming Bypass and Per-Line Dead-Block Counter" << std::endl;
    uint64_t total_fills = 0, streaming_bypass = 0, ship_mru_inserts = 0, lip_inserts = 0, bip_inserts = 0, dead_inserts = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            total_fills++;
            if (stream_table[set].streaming && line_meta[set][way].dead)
                streaming_bypass++;
            if (line_meta[set][way].rrpv == 0)
                ship_mru_inserts++;
            if (line_meta[set][way].rrpv == LIP_INSERT)
                lip_inserts++;
            if (line_meta[set][way].rrpv == BIP_INSERT)
                bip_inserts++;
            if (line_meta[set][way].dead)
                dead_inserts++;
        }
    }
    std::cout << "Fraction streaming-region bypasses: "
              << (double)streaming_bypass / total_fills << std::endl;
    std::cout << "Fraction SHiP MRU-inserts: "
              << (double)ship_mru_inserts / total_fills << std::endl;
    std::cout << "Fraction LIP-inserts: "
              << (double)lip_inserts / total_fills << std::endl;
    std::cout << "Fraction BIP-inserts: "
              << (double)bip_inserts / total_fills << std::endl;
    std::cout << "Fraction dead-block lines: "
              << (double)dead_inserts / total_fills << std::endl;
    std::cout << "PSEL value: " << psel << "/" << PSEL_MAX << std::endl;
}
void PrintStats_Heartbeat() {}