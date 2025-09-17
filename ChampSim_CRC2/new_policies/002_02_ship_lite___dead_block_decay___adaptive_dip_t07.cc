#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// RRIP definitions
#define MAX_RRPV 3 // 2 bits per line

// DIP PSEL and leader sets
#define PSEL_BITS 10
#define PSEL_MAX ((1 << PSEL_BITS) - 1)
#define DIP_LEADER_SETS 32 // 16 LIP, 16 BIP

// SHiP-lite
#define SHIP_ENTRIES 8192 // 8K entries
#define SHIP_CTR_MAX 3    // 2 bits per entry
#define SIGNATURE_BITS 6  // 6 bits per entry

// Dead-block approximation
#define DEAD_CTR_MAX 1    // 1 bit per line

struct LINE_REPL_META {
    uint8_t rrpv;            // 2 bits
    uint8_t dead_ctr;        // 1 bit
    uint16_t signature;      // 6 bits
};

std::vector<LINE_REPL_META> repl_meta(LLC_SETS * LLC_WAYS);

uint8_t SHIP_table[SHIP_ENTRIES]; // 2 bits per entry

// DIP PSEL
uint16_t PSEL = PSEL_MAX / 2;

// DIP leader sets
std::vector<uint8_t> is_lip_leader(LLC_SETS, 0);
std::vector<uint8_t> is_bip_leader(LLC_SETS, 0);

// Helper: Hash PC to signature
inline uint16_t get_signature(uint64_t PC) {
    return (PC ^ (PC >> 16)) & (SHIP_ENTRIES - 1);
}

// Dead-block global decay counter
uint64_t global_access_counter = 0;
const uint64_t DEAD_DECAY_INTERVAL = 100000; // Decay every 100K accesses

void InitReplacementState() {
    for (uint32_t s = 0; s < LLC_SETS; ++s) {
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            uint32_t idx = s * LLC_WAYS + w;
            repl_meta[idx].rrpv = MAX_RRPV;
            repl_meta[idx].dead_ctr = 0;
            repl_meta[idx].signature = 0;
        }
    }
    memset(SHIP_table, 1, sizeof(SHIP_table)); // Neutral outcome
    PSEL = PSEL_MAX / 2;

    // DIP leader sets
    for (uint32_t i = 0; i < DIP_LEADER_SETS; ++i) {
        is_lip_leader[i] = 1;
        is_bip_leader[LLC_SETS - 1 - i] = 1;
    }
    global_access_counter = 0;
}

// RRIP victim selection
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    uint32_t base = set * LLC_WAYS;
    while (true) {
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            if (repl_meta[base + w].rrpv == MAX_RRPV) {
                return w;
            }
        }
        // Increment RRPV (aging)
        for (uint32_t w = 0; w < LLC_WAYS; ++w)
            if (repl_meta[base + w].rrpv < MAX_RRPV)
                repl_meta[base + w].rrpv++;
    }
}

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
    uint32_t idx = set * LLC_WAYS + way;
    uint16_t signature = get_signature(PC);

    // Dead-block counter update: increment on hit, reset on replacement
    if (hit) {
        if (repl_meta[idx].dead_ctr < DEAD_CTR_MAX)
            repl_meta[idx].dead_ctr++;
        // SHiP outcome update
        if (SHIP_table[signature] < SHIP_CTR_MAX)
            SHIP_table[signature]++;
        repl_meta[idx].rrpv = 0; // Promote on hit
    } else {
        // DIP adaptive selection
        bool lip_mode = false, bip_mode = false;
        if (is_lip_leader[set]) lip_mode = true;
        if (is_bip_leader[set]) bip_mode = true;
        if (!lip_mode && !bip_mode)
            lip_mode = (PSEL >= (PSEL_MAX / 2));

        // SHiP bias
        uint8_t ship_hint = SHIP_table[signature];
        uint8_t insert_rrpv = MAX_RRPV;

        // Dead-block approximation: lines with dead_ctr==0 considered dead-on-arrival
        if (repl_meta[idx].dead_ctr == 0 || ship_hint == 0) {
            insert_rrpv = MAX_RRPV; // likely dead, short retention
        } else if (ship_hint >= 2 && repl_meta[idx].dead_ctr == DEAD_CTR_MAX) {
            insert_rrpv = 0; // hot PC and reused line: long retention
        } else {
            insert_rrpv = 2; // moderate
        }

        // Apply DIP mode
        if (lip_mode) {
            // LIP: always insert at MAX_RRPV unless SHiP/dead-block say otherwise
            if (insert_rrpv > 2) insert_rrpv = MAX_RRPV;
        } else if (bip_mode) {
            // BIP: insert at 0 only 1/32 times, else at MAX_RRPV
            if (rand() % 32 == 0) insert_rrpv = 0;
            else insert_rrpv = MAX_RRPV;
        }

        repl_meta[idx].rrpv = insert_rrpv;
        repl_meta[idx].signature = signature;
        repl_meta[idx].dead_ctr = 0; // reset on replacement

        // SHiP outcome
        SHIP_table[signature] = (hit ? SHIP_table[signature] : (SHIP_table[signature] ? SHIP_table[signature] - 1 : 0));
    }

    // DIP PSEL update: only on leader sets
    if (is_lip_leader[set]) {
        if (hit && type == 0 && PSEL < PSEL_MAX) PSEL++;
    }
    if (is_bip_leader[set]) {
        if (hit && type == 0 && PSEL > 0) PSEL--;
    }

    // Dead-block global decay: every DEAD_DECAY_INTERVAL accesses, decay all dead_ctr
    global_access_counter++;
    if (global_access_counter % DEAD_DECAY_INTERVAL == 0) {
        for (uint32_t i = 0; i < LLC_SETS * LLC_WAYS; ++i) {
            if (repl_meta[i].dead_ctr > 0)
                repl_meta[i].dead_ctr--;
        }
    }
}

void PrintStats() {
    std::cout << "SHiP-Lite + Dead Block Decay + Adaptive DIP stats\n";
}

void PrintStats_Heartbeat() {
    // No-op
}