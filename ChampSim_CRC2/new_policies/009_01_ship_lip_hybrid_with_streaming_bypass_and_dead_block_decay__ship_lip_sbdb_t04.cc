#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- LIP/BIP parameters ---
#define RRPV_BITS 2
#define RRPV_MAX ((1 << RRPV_BITS) - 1)
#define LIP_INSERT RRPV_MAX
#define BIP_INSERT (RRPV_MAX-1)
#define MRU_INSERT 0

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
#define STREAM_DETECT_LEN 3 // more sensitive

// --- Dead-block counter ---
#define DEAD_CTR_BITS 1 // 1 bit per line

struct LineMeta {
    uint8_t rrpv;      // 2 bits
    uint8_t signature; // 6 bits
    uint8_t dead_ctr;  // 1 bit
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

bool is_lip_leader[LLC_SETS];
bool is_bip_leader[LLC_SETS];
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
            line_meta[set][way].dead_ctr = 0;
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

// Victim selection: standard SRRIP, prefer dead blocks
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Prefer dead blocks first
    for (uint32_t way = 0; way < LLC_WAYS; ++way) {
        if (line_meta[set][way].dead_ctr == 1)
            return way;
    }
    // Then, find block with RRPV==MAX
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

        // Streaming detected: bypass fill (do not cache)
        if (streaming) {
            // Mark as dead block (will be evicted soon)
            line_meta[set][way].rrpv = RRPV_MAX;
            line_meta[set][way].dead_ctr = 1;
        }
        // SHiP high reuse: insert at MRU
        else if (ship_ctr == 3) {
            line_meta[set][way].rrpv = MRU_INSERT;
            line_meta[set][way].dead_ctr = 0;
        }
        // Otherwise: LIP/BIP insertion
        else {
            if (use_lip) {
                line_meta[set][way].rrpv = LIP_INSERT;
            } else {
                // BIP: insert at MRU with low probability (1/32), else at LIP
                if ((rand() & 31) == 0)
                    line_meta[set][way].rrpv = MRU_INSERT;
                else
                    line_meta[set][way].rrpv = LIP_INSERT;
            }
            line_meta[set][way].dead_ctr = 0;
        }

        // Set metadata
        line_meta[set][way].signature = sig;
    } else {
        // On hit: promote to MRU, mark as live
        line_meta[set][way].rrpv = MRU_INSERT;
        line_meta[set][way].dead_ctr = 0;
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

    // Dead-block counter decay: periodically mark blocks as dead if not reused
    static uint64_t access_count = 0;
    access_count++;
    if ((access_count & 0xFFF) == 0) { // every 4096 accesses
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            if (line_meta[set][w].dead_ctr == 0)
                line_meta[set][w].dead_ctr = 1; // decay to dead if not reused recently
        }
    }

    // Set-dueling PSEL update
    if (is_lip_leader[set]) {
        if (hit && psel < PSEL_MAX) psel++;
        else if (!hit && psel > 0) psel--;
    } else if (is_bip_leader[set]) {
        if (hit && psel > 0) psel--;
        else if (!hit && psel < PSEL_MAX) psel++;
    }
}

// --- Statistics ---
void PrintStats() {
    std::cout << "SHiP-LIP-SBDB Policy: SHiP-LIP Hybrid with Streaming Bypass and Dead-Block Decay" << std::endl;
    uint64_t total_fills = 0, streaming_bypass = 0, ship_mru_inserts = 0, lip_inserts = 0, bip_inserts = 0, dead_blocks = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            total_fills++;
            if (stream_table[set].streaming && line_meta[set][way].rrpv == RRPV_MAX)
                streaming_bypass++;
            if (line_meta[set][way].rrpv == MRU_INSERT)
                ship_mru_inserts++;
            if (line_meta[set][way].rrpv == LIP_INSERT)
                lip_inserts++;
            if (line_meta[set][way].rrpv != LIP_INSERT && line_meta[set][way].rrpv != MRU_INSERT)
                bip_inserts++;
            if (line_meta[set][way].dead_ctr == 1)
                dead_blocks++;
        }
    }
    std::cout << "Fraction streaming bypass: "
              << (double)streaming_bypass / total_fills << std::endl;
    std::cout << "Fraction SHiP MRU-inserts: "
              << (double)ship_mru_inserts / total_fills << std::endl;
    std::cout << "Fraction LIP-inserts: "
              << (double)lip_inserts / total_fills << std::endl;
    std::cout << "Fraction BIP-inserts: "
              << (double)bip_inserts / total_fills << std::endl;
    std::cout << "Fraction dead blocks: "
              << (double)dead_blocks / total_fills << std::endl;
    std::cout << "PSEL value: " << psel << "/" << PSEL_MAX << std::endl;
}
void PrintStats_Heartbeat() {}