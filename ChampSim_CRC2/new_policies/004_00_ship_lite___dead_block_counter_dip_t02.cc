#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// DIP definitions
#define PSEL_BITS 10
#define PSEL_MAX ((1 << PSEL_BITS) - 1)
#define DIP_LEADER_SETS 32 // 16 LIP, 16 BIP

// SHiP-lite definitions
#define SHIP_ENTRIES 8192 // 8K entries
#define SHIP_CTR_MAX 3    // 2 bits per entry
#define SIGNATURE_BITS 6  // 6 bits per entry

// Per-line metadata: dead-block counter (2 bits), LRU stack position (4 bits), SHiP signature (6 bits)
struct LINE_REPL_META {
    uint8_t dead_ctr;     // 2 bits
    uint8_t lru_pos;      // 4 bits (0=MRU, 15=LRU)
    uint16_t signature;   // 6 bits
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

// Periodic dead-block counter decay (every 100K accesses)
uint64_t access_counter = 0;
void periodic_decay() {
    if ((access_counter % 100000) == 0) {
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
            repl_meta[idx].dead_ctr = 0;
            repl_meta[idx].lru_pos = w; // initialize stack order
            repl_meta[idx].signature = 0;
        }
    }
    memset(SHIP_table, 1, sizeof(SHIP_table)); // Neutral outcome
    PSEL = PSEL_MAX / 2;

    // Set leader sets for DIP set-dueling
    for (uint32_t i = 0; i < DIP_LEADER_SETS; ++i) {
        is_lip_leader[i] = 1;
        is_bip_leader[LLC_SETS - 1 - i] = 1;
    }
    access_counter = 0;
}

uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Find LRU block (highest lru_pos)
    uint32_t base = set * LLC_WAYS;
    uint8_t max_lru = 0;
    uint32_t victim = 0;
    for (uint32_t w = 0; w < LLC_WAYS; ++w) {
        if (repl_meta[base + w].lru_pos >= max_lru) {
            max_lru = repl_meta[base + w].lru_pos;
            victim = w;
        }
    }
    return victim;
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
    access_counter++;
    periodic_decay();

    uint32_t idx = set * LLC_WAYS + way;
    // --- SHiP-lite signature extraction ---
    uint16_t signature = get_signature(PC);

    // On cache hit
    if (hit) {
        // SHiP outcome update
        if (SHIP_table[signature] < SHIP_CTR_MAX)
            SHIP_table[signature]++;
        repl_meta[idx].dead_ctr = 0; // reset dead-block counter
        repl_meta[idx].signature = signature;
        // Move to MRU
        uint32_t base = set * LLC_WAYS;
        uint8_t old_pos = repl_meta[idx].lru_pos;
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            if (repl_meta[base + w].lru_pos < old_pos)
                repl_meta[base + w].lru_pos++;
        }
        repl_meta[idx].lru_pos = 0;
    } else {
        // DIP insertion policy selection
        bool lip_mode = false, bip_mode = false;
        if (is_lip_leader[set]) lip_mode = true;
        if (is_bip_leader[set]) bip_mode = true;
        if (!lip_mode && !bip_mode)
            lip_mode = (PSEL >= (PSEL_MAX / 2));

        // SHiP prediction
        bool ship_dead = (SHIP_table[signature] == 0);

        // Dead-block counter prediction
        bool db_dead = (repl_meta[idx].dead_ctr >= 2);

        // Final insertion position
        uint8_t insert_pos = 0; // MRU
        if (ship_dead || db_dead) {
            insert_pos = LLC_WAYS - 1; // LRU
        } else {
            // DIP logic
            if (lip_mode) {
                insert_pos = 0; // LIP: always MRU
            } else if (bip_mode) {
                insert_pos = (rand() % 32 == 0) ? 0 : (LLC_WAYS - 1); // BIP: MRU 1/32, else LRU
            } else {
                insert_pos = 0; // default MRU
            }
        }

        // Update per-line metadata
        repl_meta[idx].dead_ctr = 0;
        repl_meta[idx].signature = signature;

        // Update LRU stack
        uint32_t base = set * LLC_WAYS;
        uint8_t old_pos = repl_meta[idx].lru_pos;
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            if (repl_meta[base + w].lru_pos < old_pos)
                repl_meta[base + w].lru_pos++;
        }
        repl_meta[idx].lru_pos = insert_pos;
    }

    // On eviction: increment dead-block counter if not reused
    if (!hit) {
        uint32_t victim_idx = set * LLC_WAYS + GetVictimInSet(cpu, set, nullptr, PC, paddr, type);
        if (repl_meta[victim_idx].dead_ctr < 3)
            repl_meta[victim_idx].dead_ctr++;
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
    std::cout << "SHiP-Lite + Dead-Block Counter DIP stats\n";
}

void PrintStats_Heartbeat() {
    // No-op
}