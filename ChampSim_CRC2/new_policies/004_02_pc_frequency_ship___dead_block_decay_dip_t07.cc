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

// DIP PSEL and set-dueling
#define PSEL_BITS 10
#define PSEL_MAX ((1 << PSEL_BITS) - 1)
#define DIP_LEADER_SETS 32 // 16 LIP, 16 BIP

// SHiP-lite definitions
#define SHIP_ENTRIES 8192 // 8K entries
#define SHIP_CTR_MAX 3    // 2 bits per entry
#define SIGNATURE_BITS 6  // 6 bits per entry

// Per-line dead-block counter (2 bits)
struct LINE_REPL_META {
    uint8_t rrpv;         // 2 bits
    uint16_t signature;   // 6 bits
    uint8_t outcome;      // 2 bits (SHiP)
    uint8_t dead_ctr;     // 2 bits (dead-block approximation)
};

std::vector<LINE_REPL_META> repl_meta(LLC_SETS * LLC_WAYS);

uint8_t SHIP_table[SHIP_ENTRIES]; // 6-bit signature index, 2-bit outcome

// DIP PSEL
uint16_t PSEL = PSEL_MAX / 2;

// DIP leader sets
std::vector<uint8_t> is_lip_leader(LLC_SETS, 0);
std::vector<uint8_t> is_bip_leader(LLC_SETS, 0);

// Helper: Hash PC to signature
inline uint16_t get_signature(uint64_t PC) {
    return (PC ^ (PC >> 16)) & (SHIP_ENTRIES - 1);
}

// Decay dead-block counters periodically (every 4096 fills)
uint64_t fill_count = 0;
void decay_dead_counters() {
    if ((fill_count & 0xFFF) == 0) { // every 4096 fills
        for (size_t i = 0; i < repl_meta.size(); ++i) {
            if (repl_meta[i].dead_ctr > 0)
                repl_meta[i].dead_ctr--;
        }
    }
}

void InitReplacementState() {
    for (uint32_t s = 0; s < LLC_SETS; ++s) {
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            uint32_t idx = s * LLC_WAYS + w;
            repl_meta[idx].rrpv = MAX_RRPV;
            repl_meta[idx].signature = 0;
            repl_meta[idx].outcome = 1;
            repl_meta[idx].dead_ctr = 1; // neutral start
        }
    }
    memset(SHIP_table, 1, sizeof(SHIP_table)); // Neutral outcome
    PSEL = PSEL_MAX / 2;

    // Set leader sets for DIP set-dueling
    for (uint32_t i = 0; i < DIP_LEADER_SETS; ++i) {
        is_lip_leader[i] = 1;
        is_bip_leader[LLC_SETS - 1 - i] = 1;
    }
}

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
    // --- SHiP-lite signature extraction ---
    uint16_t signature = get_signature(PC);

    // Dead-block counter decay
    fill_count++;
    decay_dead_counters();

    // On cache hit
    if (hit) {
        // SHiP outcome update
        if (SHIP_table[signature] < SHIP_CTR_MAX)
            SHIP_table[signature]++;
        repl_meta[idx].rrpv = 0; // Promote on hit
        repl_meta[idx].outcome = 1;
        // Dead-block counter: increment to indicate reuse
        if (repl_meta[idx].dead_ctr < 3) repl_meta[idx].dead_ctr++;
    } else {
        // DIP insertion policy selection
        bool lip_mode = false, bip_mode = false;
        if (is_lip_leader[set]) lip_mode = true;
        if (is_bip_leader[set]) bip_mode = true;
        if (!lip_mode && !bip_mode)
            lip_mode = (PSEL >= (PSEL_MAX / 2));

        // SHiP insertion depth
        uint8_t insert_rrpv;
        if (SHIP_table[signature] >= 2) {
            insert_rrpv = 0; // likely reusable
        } else if (SHIP_table[signature] == 1) {
            insert_rrpv = 2; // moderate
        } else {
            insert_rrpv = MAX_RRPV; // dead-on-arrival
        }

        // Dead-block counter: if decayed and low SHiP, insert at MAX_RRPV
        if (repl_meta[idx].dead_ctr == 0 && SHIP_table[signature] < 2)
            insert_rrpv = MAX_RRPV;

        // DIP mode
        if (lip_mode) {
            insert_rrpv = MAX_RRPV; // LIP: insert at distant RRPV unless SHiP says "hot"
            if (SHIP_table[signature] >= 2) insert_rrpv = 0;
        } else if (bip_mode) {
            // BRRIP-like: insert at 0 only 1/32 times, else at MAX_RRPV
            if (rand() % 32 == 0) insert_rrpv = 0;
            else insert_rrpv = MAX_RRPV;
        }

        repl_meta[idx].rrpv = insert_rrpv;
        repl_meta[idx].signature = signature;
        repl_meta[idx].outcome = 0;
        repl_meta[idx].dead_ctr = 1; // reset on fill
    }

    // PSEL update: only on leader sets
    if (is_lip_leader[set]) {
        if (hit && type == 0 && PSEL < PSEL_MAX) PSEL++;
    }
    if (is_bip_leader[set]) {
        if (hit && type == 0 && PSEL > 0) PSEL--;
    }
}

void PrintStats() {
    std::cout << "PC-Frequency SHiP + Dead-Block Decay DIP stats\n";
    // Optionally print SHiP histogram, dead-block counter stats, PSEL value
}

void PrintStats_Heartbeat() {
    // No-op
}