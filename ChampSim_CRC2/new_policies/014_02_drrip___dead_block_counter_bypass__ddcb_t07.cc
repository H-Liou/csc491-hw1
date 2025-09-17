#include <vector>
#include <cstdint>
#include <iostream>
#include <algorithm>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// DRRIP parameters
#define RRPV_BITS 2
#define RRPV_MAX ((1<<RRPV_BITS)-1)
#define SRRIP_INSERT 0
#define BRRIP_INSERT (RRPV_MAX-1)

// Dead-block counter parameters
#define DEADCTR_BITS 2
#define DEADCTR_MAX ((1<<DEADCTR_BITS)-1)
#define DEADCTR_THRESHOLD (DEADCTR_MAX-1)

// DRRIP set-dueling
#define NUM_LEADER_SETS 32
#define PSEL_BITS 10
#define PSEL_MAX ((1<<PSEL_BITS)-1)
#define PSEL_INIT (PSEL_MAX/2)

// Identify leader sets
std::vector<uint8_t> leader_sets(LLC_SETS, 0); // 0: follower, 1: SRRIP leader, 2: BRRIP leader
uint32_t sr_leader_cnt = 0, br_leader_cnt = 0;

// Block state
struct block_state_t {
    uint8_t rrpv;      // 2 bits: RRIP value
    uint8_t deadctr;   // 2 bits: dead-block counter
};
std::vector<std::vector<block_state_t>> blocks(LLC_SETS, std::vector<block_state_t>(LLC_WAYS));

// PSEL counter
uint32_t PSEL = PSEL_INIT;

// Random for set selection
inline uint32_t simple_hash(uint32_t set) { return (set * 13 + set/7) % LLC_SETS; }

void InitReplacementState() {
    sr_leader_cnt = 0; br_leader_cnt = 0;
    for (uint32_t s = 0; s < LLC_SETS; s++) {
        for (uint32_t w = 0; w < LLC_WAYS; w++) {
            blocks[s][w] = {RRPV_MAX, 0}; // LRU, not dead
        }
        leader_sets[s] = 0;
    }
    // Assign leader sets
    for (uint32_t i = 0; i < NUM_LEADER_SETS; i++) {
        uint32_t sr_set = (i * 37) % LLC_SETS;
        uint32_t br_set = (i * 71 + 13) % LLC_SETS;
        if (leader_sets[sr_set] == 0) { leader_sets[sr_set] = 1; sr_leader_cnt++; }
        if (leader_sets[br_set] == 0) { leader_sets[br_set] = 2; br_leader_cnt++; }
    }
    PSEL = PSEL_INIT;
}

// Find victim in the set (RRIP)
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

// Update replacement state
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
    // Dead-block counter decay every 4096 fills per set (approx)
    static uint32_t global_decay_ctr = 0;
    global_decay_ctr++;
    if (global_decay_ctr % (LLC_SETS*2) == 0) {
        for (uint32_t s = 0; s < LLC_SETS; s++)
            for (uint32_t w = 0; w < LLC_WAYS; w++)
                if (blocks[s][w].deadctr > 0)
                    blocks[s][w].deadctr--;
    }

    // On hit: set block to MRU, reset dead-block counter
    if (hit) {
        blocks[set][way].rrpv = SRRIP_INSERT;
        blocks[set][way].deadctr = 0;
        return;
    }

    // On miss/fill: increment dead-block counter for victim
    if (blocks[set][way].deadctr < DEADCTR_MAX)
        blocks[set][way].deadctr++;

    // Dead-block bypass: if victim is dead, new block is likely dead too
    if (blocks[set][way].deadctr >= DEADCTR_THRESHOLD) {
        // Do not insert block (simulate bypass by setting RRPV=RRPV_MAX)
        blocks[set][way].rrpv = RRPV_MAX;
        blocks[set][way].deadctr = 0;
        return;
    }

    // DRRIP insertion depth
    uint8_t ins_rrpv;
    // Leader sets decide SRRIP or BRRIP, others follow PSEL majority
    if (leader_sets[set] == 1) { // SRRIP leader
        ins_rrpv = SRRIP_INSERT;
    } else if (leader_sets[set] == 2) { // BRRIP leader
        ins_rrpv = BRRIP_INSERT;
    } else {
        ins_rrpv = (PSEL >= PSEL_MAX/2) ? SRRIP_INSERT : BRRIP_INSERT;
    }
    blocks[set][way].rrpv = ins_rrpv;
    blocks[set][way].deadctr = 0;

    // PSEL update (on misses in leader sets)
    if (leader_sets[set] == 1) {
        if (!hit && PSEL < PSEL_MAX) PSEL++;
    } else if (leader_sets[set] == 2) {
        if (!hit && PSEL > 0) PSEL--;
    }
}

void PrintStats() {
    uint64_t dead_blocks = 0, total_blocks = 0;
    for (uint32_t s = 0; s < LLC_SETS; s++)
        for (uint32_t w = 0; w < LLC_WAYS; w++) {
            if (blocks[s][w].deadctr >= DEADCTR_THRESHOLD) dead_blocks++;
            total_blocks++;
        }
    std::cout << "DDCB: Dead blocks=" << dead_blocks << "/" << total_blocks << std::endl;
    std::cout << "DDCB: PSEL=" << PSEL << "/" << PSEL_MAX << std::endl;
    std::cout << "DDCB: Leader sets: SRRIP=" << sr_leader_cnt << " BRRIP=" << br_leader_cnt << std::endl;
}

void PrintStats_Heartbeat() {
    // No periodic stats needed
}