#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- DIP parameters ---
#define NUM_LEADER_SETS 32
#define PSEL_BITS 10
#define PSEL_MAX ((1 << PSEL_BITS) - 1)
#define LIP_POLICY 0
#define BIP_POLICY 1

// --- Streaming detector parameters ---
#define STREAM_DETECT_LEN 4
#define STREAM_DELTA_BITS 16

// --- Metadata structures ---
struct StreamDetector {
    uint16_t last_addr_low;
    uint16_t last_delta;
    uint8_t streak;
};

struct LineMeta {
    uint8_t rrpv; // 2 bits
};

// --- Global state ---
StreamDetector stream_table[LLC_SETS];
LineMeta line_meta[LLC_SETS][LLC_WAYS];

// DIP: Set selection and PSEL counter
uint32_t leader_sets[NUM_LEADER_SETS];
uint16_t psel = PSEL_MAX / 2; // Initialize to mid value

// --- Helper functions ---
uint32_t get_leader_set_index(uint32_t set) {
    // Simple mapping: evenly spaced leader sets
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i) {
        if (leader_sets[i] == set)
            return i;
    }
    return NUM_LEADER_SETS; // not a leader set
}

bool is_lip_leader(uint32_t set) {
    // First half of leader sets are LIP, second half are BIP
    uint32_t idx = get_leader_set_index(set);
    return idx < NUM_LEADER_SETS / 2;
}

bool is_bip_leader(uint32_t set) {
    uint32_t idx = get_leader_set_index(set);
    return idx >= NUM_LEADER_SETS / 2 && idx < NUM_LEADER_SETS;
}

// --- Initialization ---
void InitReplacementState() {
    memset(stream_table, 0, sizeof(stream_table));
    memset(line_meta, 0, sizeof(line_meta));

    // Set all RRPVs to max (3)
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            line_meta[set][way].rrpv = 3;

    // Evenly space out leader sets
    uint32_t interval = LLC_SETS / NUM_LEADER_SETS;
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i)
        leader_sets[i] = i * interval;

    psel = PSEL_MAX / 2;
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

// --- Victim selection: Standard SRRIP ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // SRRIP: Search for RRPV==3
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (line_meta[set][way].rrpv == 3)
                return way;
        }
        // Increment all RRPVs
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (line_meta[set][way].rrpv < 3)
                line_meta[set][way].rrpv++;
        }
    }
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

    uint32_t leader_idx = get_leader_set_index(set);
    bool is_leader = (leader_idx < NUM_LEADER_SETS);

    // --- On fill (miss) ---
    if (!hit) {
        uint8_t insert_rrpv = 3; // default: distant (SRRIP)

        if (streaming) {
            // Streaming block: always insert at distant RRPV
            insert_rrpv = 3;
        } else {
            // DIP-style: leader sets choose, followers use PSEL
            if (is_leader) {
                if (is_lip_leader(set)) {
                    insert_rrpv = 3; // LIP: always distant
                } else if (is_bip_leader(set)) {
                    // BIP: mostly distant, sometimes MRU
                    static uint64_t fill_count = 0;
                    fill_count++;
                    if ((fill_count & 0x1F) == 0) // 1/32 fills at MRU
                        insert_rrpv = 0;
                    else
                        insert_rrpv = 3;
                }
            } else {
                // Followers use PSEL state
                if (psel >= PSEL_MAX / 2) {
                    // BIP wins
                    static uint64_t fill_count = 0;
                    fill_count++;
                    if ((fill_count & 0x1F) == 0)
                        insert_rrpv = 0;
                    else
                        insert_rrpv = 3;
                } else {
                    // LIP wins
                    insert_rrpv = 3;
                }
            }
        }
        line_meta[set][way].rrpv = insert_rrpv;
    } else {
        // --- On hit: promote to MRU ---
        line_meta[set][way].rrpv = 0;

        // DIP: update PSEL in leader sets
        if (is_leader) {
            if (is_lip_leader(set)) {
                // LIP leader: increment PSEL on hit
                if (psel < PSEL_MAX)
                    psel++;
            } else if (is_bip_leader(set)) {
                // BIP leader: decrement PSEL on hit
                if (psel > 0)
                    psel--;
            }
        }
    }
}

// --- Stats ---
void PrintStats() {
    std::cout << "ADS-B Policy: Adaptive Dueling Insertion with Streaming Bypass" << std::endl;
    std::cout << "PSEL final value: " << psel << std::endl;
}
void PrintStats_Heartbeat() {}