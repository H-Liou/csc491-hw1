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
#define BRRIP_INSERT_PROB 32             // 1/32 probability for BRRIP long insertion

// --- Set-dueling parameters ---
#define DUEL_LEADER_SETS 32              // 32 leader sets each for SRRIP and BRRIP
#define PSEL_BITS 10
#define PSEL_MAX ((1 << PSEL_BITS) - 1)

#define SRRIP_LEADER_BASE 0
#define BRRIP_LEADER_BASE (DUEL_LEADER_SETS)
#define NORMAL_SET_BASE (DUEL_LEADER_SETS * 2)

// --- SHiP parameters ---
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

// DRRIP set-dueling
uint16_t psel; // 10-bit

// Helper: extract SHiP signature (6 bits from PC)
inline uint8_t get_signature(uint64_t PC) {
    return (uint8_t)((PC >> 2) ^ (PC >> 7)) & ((1<<SHIP_SIG_BITS)-1);
}

// --- Initialization ---
void InitReplacementState() {
    memset(line_meta, 0, sizeof(line_meta));
    memset(stream_table, 0, sizeof(stream_table));
    memset(ship_table, 0, sizeof(ship_table));
    psel = PSEL_MAX / 2;
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

    // Determine set type: leader or follower
    bool is_srrip_leader = (set >= SRRIP_LEADER_BASE && set < SRRIP_LEADER_BASE + DUEL_LEADER_SETS);
    bool is_brrip_leader = (set >= BRRIP_LEADER_BASE && set < BRRIP_LEADER_BASE + DUEL_LEADER_SETS);
    bool use_srrip = false, use_brrip = false;
    if (is_srrip_leader)
        use_srrip = true;
    else if (is_brrip_leader)
        use_brrip = true;
    else
        use_srrip = (psel >= (PSEL_MAX / 2));

    // --- SHiP training: on eviction, update SHiP table for victim block ---
    if (!hit) {
        uint8_t evict_sig = line_meta[set][way].signature;
        if (evict_sig < SHIP_TABLE_SIZE) {
            // If block was not reused (never hit), decrement SHiP counter
            // If block was reused (hit before eviction), increment
            // We use hit==0 for not reused, hit==1 for reused (last fill's block)
            // But we lack true dead-block tracking, so approximate: increment on hit, decrement on miss
            if (ship_table[evict_sig] > 0)
                ship_table[evict_sig]--;
        }
    }

    if (!hit) {
        // Insert new block
        line_meta[set][way].signature = sig;

        // Streaming-phase: always insert at RRPV_MAX (LRU)
        if (streaming) {
            line_meta[set][way].rrpv = RRPV_MAX;
        } else {
            // SHiP-based insertion: if PC signature shows reuse (counter >=2), insert at RRPV=0 (MRU)
            // Otherwise use DRRIP's chosen insertion depth
            uint8_t ctr = ship_table[sig];

            if (ctr >= 2) {
                line_meta[set][way].rrpv = 0;
            } else {
                // DRRIP logic: SRRIP inserts at RRPV=2 (long), BRRIP inserts at RRPV=3 (very long) 1/32 of time
                if (use_srrip) {
                    line_meta[set][way].rrpv = RRPV_MAX - 1; // SRRIP: insert at 2
                } else {
                    // BRRIP: insert at RRPV=3 with 31/32 probability, at 2 otherwise
                    if ((rand() % BRRIP_INSERT_PROB) == 0)
                        line_meta[set][way].rrpv = RRPV_MAX - 1;
                    else
                        line_meta[set][way].rrpv = RRPV_MAX;
                }
            }
        }
    } else {
        // On hit: promote to MRU
        line_meta[set][way].rrpv = 0;
        // SHiP: increment outcome counter for this PC signature
        if (ship_table[sig] < 3)
            ship_table[sig]++;
    }

    // Update PSEL on leader sets
    if (is_srrip_leader && !hit) {
        if (psel < PSEL_MAX) psel++;
    } else if (is_brrip_leader && !hit) {
        if (psel > 0) psel--;
    }
}

// --- Stats ---
void PrintStats() {
    std::cout << "DRRIP-SHiP-SPAI Policy: DRRIP set-dueling + SHiP-lite + Streaming-Phase Adaptive Insertion" << std::endl;
    uint64_t streaming_sets = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        if (stream_table[set].streaming) streaming_sets++;
    }
    std::cout << "Streaming sets: " << streaming_sets << "/" << LLC_SETS << std::endl;
    std::cout << "PSEL value: " << psel << std::endl;
}
void PrintStats_Heartbeat() {}