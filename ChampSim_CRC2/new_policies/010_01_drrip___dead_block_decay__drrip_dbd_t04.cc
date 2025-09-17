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
#define SRRIP_LEADER_SETS NUM_LEADER_SETS
#define BRRIP_LEADER_SETS NUM_LEADER_SETS

// Dead-block approximation
#define DEAD_BITS 2
#define DEAD_MAX ((1<<DEAD_BITS)-1)
#define DECAY_INTERVAL 4096 // Decay every N fills

struct block_state_t {
    uint8_t rrpv;      // 2 bits: RRIP value
    uint8_t dead_cnt;  // 2 bits: dead-block counter
};

std::vector<std::vector<block_state_t>> blocks(LLC_SETS, std::vector<block_state_t>(LLC_WAYS));

// DRRIP PSEL
uint16_t psel = PSEL_MAX/2;

// Leader sets: statically assigned
std::vector<uint8_t> is_leader(LLC_SETS, 0); // 0: follower, 1: SRRIP leader, 2: BRRIP leader

// Fill counter for decay
uint64_t fill_count = 0;

// Initialize replacement state
void InitReplacementState() {
    for(uint32_t s=0; s<LLC_SETS; s++) {
        for(uint32_t w=0; w<LLC_WAYS; w++) {
            blocks[s][w] = {RRPV_MAX, DEAD_MAX}; // RRPV, dead_cnt
        }
        // Assign leader sets: first N for SRRIP, next N for BRRIP, rest are followers
        if(s < SRRIP_LEADER_SETS)
            is_leader[s] = 1;
        else if(s >= LLC_SETS - BRRIP_LEADER_SETS)
            is_leader[s] = 2;
        else
            is_leader[s] = 0;
    }
    psel = PSEL_MAX/2;
    fill_count = 0;
}

// Find victim in the set (prefer dead blocks, else RRIP logic)
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // First, look for blocks with dead_cnt==0 (dead-block approx)
    for(uint32_t w=0; w<LLC_WAYS; w++) {
        if(blocks[set][w].dead_cnt == 0)
            return w;
    }
    // Otherwise, RRIP victim selection
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
    // On hit: set block to MRU, increment dead_cnt (max DEAD_MAX)
    if(hit) {
        blocks[set][way].rrpv = SRRIP_INSERT;
        if(blocks[set][way].dead_cnt < DEAD_MAX)
            blocks[set][way].dead_cnt++;
        return;
    }

    // On fill/replace: reset dead_cnt for incoming block
    blocks[set][way].dead_cnt = DEAD_MAX;

    // DRRIP: choose insertion policy
    uint8_t ins_rrpv;
    if(is_leader[set] == 1) { // SRRIP leader
        ins_rrpv = SRRIP_INSERT;
    } else if(is_leader[set] == 2) { // BRRIP leader
        // BRRIP: insert at BRRIP_INSERT with probability 1/32, else at RRPV_MAX
        if((rand() & 31) == 0)
            ins_rrpv = BRRIP_INSERT;
        else
            ins_rrpv = RRPV_MAX;
    } else {
        // Follower sets: use PSEL to choose
        if(psel >= PSEL_MAX/2) {
            ins_rrpv = SRRIP_INSERT;
        } else {
            if((rand() & 31) == 0)
                ins_rrpv = BRRIP_INSERT;
            else
                ins_rrpv = RRPV_MAX;
        }
    }
    blocks[set][way].rrpv = ins_rrpv;

    // Update PSEL on leader sets
    if(is_leader[set] == 1) { // SRRIP
        if(hit && psel < PSEL_MAX) psel++;
    } else if(is_leader[set] == 2) { // BRRIP
        if(hit && psel > 0) psel--;
    }

    // Dead-block decay: every DECAY_INTERVAL fills, decrement all dead_cnt
    fill_count++;
    if(fill_count % DECAY_INTERVAL == 0) {
        for(uint32_t s=0; s<LLC_SETS; s++)
            for(uint32_t w=0; w<LLC_WAYS; w++)
                if(blocks[s][w].dead_cnt > 0)
                    blocks[s][w].dead_cnt--;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    int dead_blocks = 0, live_blocks = 0;
    for(uint32_t s=0; s<LLC_SETS; s++)
        for(uint32_t w=0; w<LLC_WAYS; w++) {
            if(blocks[s][w].dead_cnt == 0)
                dead_blocks++;
            else
                live_blocks++;
        }
    std::cout << "DRRIP-DBD: Dead blocks = " << dead_blocks << ", Live blocks = " << live_blocks << std::endl;
    std::cout << "DRRIP-DBD: Final PSEL = " << psel << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // No periodic stats needed
}