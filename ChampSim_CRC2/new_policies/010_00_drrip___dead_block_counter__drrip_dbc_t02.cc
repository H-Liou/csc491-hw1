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

// DRRIP set-dueling
#define PSEL_BITS 10
#define PSEL_MAX ((1<<PSEL_BITS)-1)
#define NUM_LEADER_SETS 32
#define LEADER_SET_STRIDE (LLC_SETS/NUM_LEADER_SETS)

// Dead-block counter
#define DEAD_BITS 2
#define DEAD_MAX ((1<<DEAD_BITS)-1)
#define DEAD_THRESHOLD DEAD_MAX // Prefer to evict blocks with max dead count

struct block_state_t {
    uint8_t rrpv;      // 2 bits: RRIP value
    uint8_t dead_cnt;  // 2 bits: dead-block counter
};

std::vector<std::vector<block_state_t>> blocks(LLC_SETS, std::vector<block_state_t>(LLC_WAYS));

// DRRIP set-dueling
std::vector<uint8_t> is_srrip_leader(LLC_SETS, 0);
std::vector<uint8_t> is_brrip_leader(LLC_SETS, 0);
uint16_t psel = PSEL_MAX/2;

// Utility: assign leader sets for SRRIP and BRRIP
void assign_leader_sets() {
    for(uint32_t i=0; i<NUM_LEADER_SETS; i++) {
        uint32_t srrip_set = i * LEADER_SET_STRIDE;
        uint32_t brrip_set = srrip_set + LEADER_SET_STRIDE/2;
        if(srrip_set < LLC_SETS)
            is_srrip_leader[srrip_set] = 1;
        if(brrip_set < LLC_SETS)
            is_brrip_leader[brrip_set] = 1;
    }
}

// Initialize replacement state
void InitReplacementState() {
    for(uint32_t s=0; s<LLC_SETS; s++) {
        for(uint32_t w=0; w<LLC_WAYS; w++) {
            blocks[s][w] = {RRPV_MAX, 0}; // RRPV, dead_cnt
        }
    }
    assign_leader_sets();
    psel = PSEL_MAX/2;
}

// Find victim in the set
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Prefer to evict blocks with high dead-block counter
    for(uint32_t w=0; w<LLC_WAYS; w++) {
        if(blocks[set][w].dead_cnt >= DEAD_THRESHOLD)
            return w;
    }
    // Standard RRIP victim selection
    while(true) {
        for(uint32_t w=0; w<LLC_WAYS; w++)
            if(blocks[set][w].rrpv == RRPV_MAX)
                return w;
        for(uint32_t w=0; w<LLC_WAYS; w++)
            if(blocks[set][w].rrpv < RRPV_MAX)
                blocks[set][w].rrpv++;
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
    // On hit: set block to MRU, reset dead-block counter
    if(hit) {
        blocks[set][way].rrpv = SRRIP_INSERT;
        blocks[set][way].dead_cnt = 0;
        // Update PSEL for leader sets
        if(is_srrip_leader[set] && psel < PSEL_MAX)
            psel++;
        if(is_brrip_leader[set] && psel > 0)
            psel--;
        return;
    }

    // On fill/replace: increment dead-block counter for victim block
    if(blocks[set][way].dead_cnt < DEAD_MAX)
        blocks[set][way].dead_cnt++;

    // Decide insertion RRPV (DRRIP)
    uint8_t ins_rrpv;
    if(is_srrip_leader[set])
        ins_rrpv = SRRIP_INSERT;
    else if(is_brrip_leader[set])
        ins_rrpv = BRRIP_INSERT;
    else
        ins_rrpv = (psel >= PSEL_MAX/2) ? SRRIP_INSERT : BRRIP_INSERT;

    blocks[set][way].rrpv = ins_rrpv;
    blocks[set][way].dead_cnt = 0; // reset on fill
}

// Print end-of-simulation statistics
void PrintStats() {
    int dead_blocks = 0, reused_blocks = 0;
    for(uint32_t s=0; s<LLC_SETS; s++) {
        for(uint32_t w=0; w<LLC_WAYS; w++) {
            if(blocks[s][w].dead_cnt >= DEAD_THRESHOLD)
                dead_blocks++;
            else
                reused_blocks++;
        }
    }
    std::cout << "DRRIP-DBC: Dead blocks = " << dead_blocks << ", Reused blocks = " << reused_blocks << std::endl;
    std::cout << "DRRIP-DBC: PSEL = " << psel << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // No periodic stats needed
}