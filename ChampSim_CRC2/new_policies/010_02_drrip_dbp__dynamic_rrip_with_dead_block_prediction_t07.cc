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
#define SRRIP_INSERT 1
#define BRRIP_INSERT 3
#define INSERT_PROB 32 // 1/32 for BRRIP

// Set-dueling
#define NUM_LEADER_SETS 64
#define PSEL_BITS 10
#define PSEL_MAX ((1<<PSEL_BITS)-1)
#define PSEL_MID (PSEL_MAX/2)

// Dead-block predictor: 2b per block, periodic decay
#define REUSE_MAX 3
#define DECAY_PERIOD 8192

struct block_state_t {
    uint8_t rrpv;      // 2 bits: RRIP value
    uint8_t reuse;     // 2 bits: dead-block predictor
};

std::vector<std::vector<block_state_t>> blocks(LLC_SETS, std::vector<block_state_t>(LLC_WAYS));

// Set-dueling: assign NUM_LEADER_SETS for SRRIP and BRRIP each
std::vector<uint8_t> leader_type(LLC_SETS, 0); // 1:SRRIP, 2:BRRIP, 0:normal

uint16_t psel = PSEL_MID;

// Global access counter for decay
uint64_t global_access = 0;

// Assign leader sets evenly
void assign_leader_sets() {
    for(uint32_t i=0; i<NUM_LEADER_SETS; i++) {
        leader_type[i] = 1; // SRRIP leader
    }
    for(uint32_t i=NUM_LEADER_SETS; i<2*NUM_LEADER_SETS; i++) {
        leader_type[i] = 2; // BRRIP leader
    }
}

void InitReplacementState() {
    for(uint32_t s=0; s<LLC_SETS; s++) {
        for(uint32_t w=0; w<LLC_WAYS; w++) {
            blocks[s][w] = {RRPV_MAX, 0};
        }
    }
    assign_leader_sets();
    psel = PSEL_MID;
    global_access = 0;
}

// DRRIP victim selection: evict highest RRPV
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    while(true) {
        for(uint32_t w=0; w<LLC_WAYS; w++)
            if(blocks[set][w].rrpv == RRPV_MAX)
                return w;
        for(uint32_t w=0; w<LLC_WAYS; w++)
            if(blocks[set][w].rrpv < RRPV_MAX)
                blocks[set][w].rrpv++;
    }
}

// Dead-block decay: periodically halve reuse counters
void decay_deadblock_predictor() {
    for(uint32_t s=0; s<LLC_SETS; s++)
        for(uint32_t w=0; w<LLC_WAYS; w++)
            blocks[s][w].reuse >>= 1;
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
    global_access++;

    // Periodic decay of dead-block predictor
    if((global_access % DECAY_PERIOD)==0)
        decay_deadblock_predictor();

    // On hit: set block to MRU, increment reuse
    if(hit) {
        blocks[set][way].rrpv = 0;
        if(blocks[set][way].reuse < REUSE_MAX)
            blocks[set][way].reuse++;
        return;
    }

    // On replacement: reset dead-block predictor for victim
    blocks[set][way].reuse = 0;

    // Choose insertion RRPV (SRRIP or BRRIP, possibly overridden by dead-block predictor)
    uint8_t ins_rrpv;
    uint8_t set_type = leader_type[set];

    // DRRIP set-dueling logic
    if(set_type == 1) { // SRRIP leader
        ins_rrpv = SRRIP_INSERT;
    } else if(set_type == 2) { // BRRIP leader
        ins_rrpv = BRRIP_INSERT;
    } else { // Follower set
        if(psel >= PSEL_MID)
            ins_rrpv = SRRIP_INSERT;
        else
            ins_rrpv = BRRIP_INSERT;
    }

    // Dead-block predictor override:
    // If previous block in this way was reused recently, insert at MRU.
    // If not reused, insert at LRU.
    if(blocks[set][way].reuse == 0)
        ins_rrpv = RRPV_MAX;
    else if(blocks[set][way].reuse >= 2)
        ins_rrpv = 0;

    // Update block state
    blocks[set][way].rrpv = ins_rrpv;
    blocks[set][way].reuse = 0;

    // Set-dueling: update PSEL counters only for leader sets
    if(set_type == 1) { // SRRIP leader
        if(hit && blocks[set][way].rrpv == 0 && psel < PSEL_MAX)
            psel++;
    }
    else if(set_type == 2) { // BRRIP leader
        if(hit && blocks[set][way].rrpv == 0 && psel > 0)
            psel--;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    int dead_blocks=0, reused_blocks=0;
    for(uint32_t s=0; s<LLC_SETS; s++)
        for(uint32_t w=0; w<LLC_WAYS; w++) {
            if(blocks[s][w].reuse == 0) dead_blocks++;
            else reused_blocks++;
        }
    std::cout << "DRRIP-DBP: Dead blocks = " << dead_blocks << ", Reused blocks = " << reused_blocks << std::endl;
    std::cout << "DRRIP-DBP: PSEL = " << psel << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // No periodic stats needed
}