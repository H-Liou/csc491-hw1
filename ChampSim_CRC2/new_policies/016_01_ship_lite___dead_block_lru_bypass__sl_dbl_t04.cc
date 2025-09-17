#include <vector>
#include <cstdint>
#include <iostream>
#include <algorithm>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// RRIP parameters
#define RRPV_BITS 2
#define RRPV_MAX ((1<<RRPV_BITS)-1)
#define SRRIP_INSERT 0
#define BRRIP_INSERT (RRPV_MAX-1)

// SHiP-lite parameters
#define SHIP_SIG_BITS 6
#define SHIP_TABLE_SIZE (1<<SHIP_SIG_BITS) // 64
#define SHIP_ENTRIES (LLC_SETS)            // 2048
#define SHIP_COUNTER_BITS 2
#define SHIP_MAX ((1<<SHIP_COUNTER_BITS)-1)
#define SHIP_THRESHOLD 1

// Dead-block counter
#define DEAD_BITS 2
#define DEAD_MAX ((1<<DEAD_BITS)-1)
#define DEAD_DECAY_INTERVAL 8192 // Decay every 8K fills

// Set-dueling for SHiP vs RRIP
#define NUM_LEADER_SETS 32
#define PSEL_BITS 10
#define PSEL_MAX ((1<<PSEL_BITS)-1)
#define PSEL_INIT (PSEL_MAX/2)

// Block state
struct block_state_t {
    uint8_t rrpv;      // 2 bits: RRIP value
    uint8_t ship_sig;  // 6 bits: PC signature
    uint8_t dead_ctr;  // 2 bits: dead-block reuse counter
    bool valid;
};
std::vector<std::vector<block_state_t>> blocks(LLC_SETS, std::vector<block_state_t>(LLC_WAYS));

// SHiP-lite table: per-signature outcome counter
struct ship_entry_t {
    uint8_t counter; // 2 bits
};
std::vector<ship_entry_t> ship_table(SHIP_TABLE_SIZE * SHIP_ENTRIES);

// Set-dueling leader sets
std::vector<uint8_t> leader_sets(LLC_SETS, 0); // 0: follower, 1: SHiP leader, 2: RRIP leader
uint32_t ship_leader_cnt = 0, rrip_leader_cnt = 0;
uint32_t PSEL = PSEL_INIT;

// Dead-block decay
uint64_t global_fill_ctr = 0;

// --- Helper: get PC signature ---
inline uint8_t get_ship_sig(uint64_t PC, uint32_t set) {
    // Combine PC and set for more diversity
    return ((PC >> 2) ^ set) & (SHIP_TABLE_SIZE-1);
}

// --- Helper: get SHiP table index ---
inline uint32_t get_ship_idx(uint32_t set, uint8_t sig) {
    return (set * SHIP_TABLE_SIZE) + sig;
}

// --- Init ---
void InitReplacementState() {
    ship_leader_cnt = 0; rrip_leader_cnt = 0;
    for (uint32_t s = 0; s < LLC_SETS; s++) {
        for (uint32_t w = 0; w < LLC_WAYS; w++) {
            blocks[s][w] = {RRPV_MAX, 0, DEAD_MAX, false};
        }
        leader_sets[s] = 0;
    }
    for (uint32_t i = 0; i < NUM_LEADER_SETS; i++) {
        uint32_t ship_set = (i * 37) % LLC_SETS;
        uint32_t rrip_set = (i * 71 + 13) % LLC_SETS;
        if (leader_sets[ship_set] == 0) { leader_sets[ship_set] = 1; ship_leader_cnt++; }
        if (leader_sets[rrip_set] == 0) { leader_sets[rrip_set] = 2; rrip_leader_cnt++; }
    }
    for (auto &entry : ship_table) entry.counter = SHIP_THRESHOLD;
    PSEL = PSEL_INIT;
    global_fill_ctr = 0;
}

// --- Victim selection (RRIP) ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    while(true) {
        for (uint32_t w = 0; w < LLC_WAYS; w++) {
            if (blocks[set][w].rrpv == RRPV_MAX)
                return w;
        }
        for (uint32_t w = 0; w < LLC_WAYS; w++) {
            if (blocks[set][w].rrpv < RRPV_MAX)
                blocks[set][w].rrpv++;
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
    global_fill_ctr++;

    // Dead-block decay: periodically decay all counters
    if ((global_fill_ctr & (DEAD_DECAY_INTERVAL-1)) == 0) {
        for (uint32_t s = 0; s < LLC_SETS; s++)
            for (uint32_t w = 0; w < LLC_WAYS; w++)
                if (blocks[s][w].dead_ctr > 0)
                    blocks[s][w].dead_ctr--;
    }

    // Get PC signature
    uint8_t sig = get_ship_sig(PC, set);
    uint32_t ship_idx = get_ship_idx(set, sig);

    // On hit: set block to MRU, increment SHiP counter and dead-block counter
    if (hit) {
        blocks[set][way].rrpv = SRRIP_INSERT;
        blocks[set][way].ship_sig = sig;
        blocks[set][way].valid = true;
        if (ship_table[ship_idx].counter < SHIP_MAX)
            ship_table[ship_idx].counter++;
        if (blocks[set][way].dead_ctr < DEAD_MAX)
            blocks[set][way].dead_ctr++;
        return;
    }

    // On miss: update SHiP counter for victim block, decay dead-block counter if victim not reused
    if (blocks[set][way].valid) {
        uint8_t victim_sig = blocks[set][way].ship_sig;
        uint32_t victim_idx = get_ship_idx(set, victim_sig);
        if (ship_table[victim_idx].counter > 0)
            ship_table[victim_idx].counter--;
        // If victim dead_ctr == 0, it was never reused
        // (No action here: insertion policy will use this info)
    }

    // Decide insertion depth
    uint8_t ins_rrpv;
    bool ship_predicts_reuse = (ship_table[ship_idx].counter >= SHIP_THRESHOLD);
    bool victim_dead = (blocks[set][way].dead_ctr == 0);

    // Leader sets: SHiP vs RRIP, others follow PSEL
    if (leader_sets[set] == 1) { // SHiP leader
        ins_rrpv = (ship_predicts_reuse && !victim_dead) ? SRRIP_INSERT : BRRIP_INSERT;
    } else if (leader_sets[set] == 2) { // RRIP leader
        ins_rrpv = BRRIP_INSERT;
    } else {
        ins_rrpv = (PSEL >= PSEL_MAX/2) ?
            ((ship_predicts_reuse && !victim_dead) ? SRRIP_INSERT : BRRIP_INSERT)
            : BRRIP_INSERT;
    }
    blocks[set][way].rrpv = ins_rrpv;
    blocks[set][way].ship_sig = sig;
    blocks[set][way].valid = true;
    blocks[set][way].dead_ctr = 0; // New block starts at 0 (not yet reused)

    // PSEL update (misses in leader sets)
    if (leader_sets[set] == 1) {
        if (!hit && PSEL < PSEL_MAX) PSEL++;
    } else if (leader_sets[set] == 2) {
        if (!hit && PSEL > 0) PSEL--;
    }
}

// --- Print stats ---
void PrintStats() {
    uint64_t dead_lines = 0, total_lines = 0;
    for (uint32_t s = 0; s < LLC_SETS; s++)
        for (uint32_t w = 0; w < LLC_WAYS; w++) {
            total_lines++;
            if (blocks[s][w].dead_ctr == 0) dead_lines++;
        }
    std::cout << "SL-DBL: Dead lines=" << dead_lines << "/" << total_lines << std::endl;
    std::cout << "SL-DBL: PSEL=" << PSEL << "/" << PSEL_MAX << std::endl;
    std::cout << "SL-DBL: Leader sets: SHiP=" << ship_leader_cnt << " RRIP=" << rrip_leader_cnt << std::endl;
}

// --- Print heartbeat stats ---
void PrintStats_Heartbeat() {
    // No periodic stats needed
}