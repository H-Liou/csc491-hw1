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
#define MRU_INSERT 0
#define DISTANT_INSERT RRPV_MAX

// Dead-block counter
#define DEAD_BITS 2
#define DEAD_MAX ((1<<DEAD_BITS)-1)
#define DEAD_THRESHOLD (DEAD_MAX)

// Streaming detector
#define STREAM_WINDOW 8
#define STREAM_DELTA_THRESHOLD 6

struct block_state_t {
    uint8_t rrpv;       // 2 bits: RRIP value
    uint8_t dead_ctr;   // 2 bits: dead-block counter
};

std::vector<std::vector<block_state_t>> blocks(LLC_SETS, std::vector<block_state_t>(LLC_WAYS));

// Streaming detector: per-set
struct stream_state_t {
    uint64_t last_addr;
    int8_t deltas[STREAM_WINDOW];
    uint8_t idx;
    uint8_t stream_flag;
};
std::vector<stream_state_t> stream_state(LLC_SETS);

// Dead-block decay: periodic decay counter
uint64_t global_decay_ctr = 0;
#define DECAY_PERIOD 4096 // decay every 4096 fills

// Utility: streaming detector
void update_stream_detector(uint32_t set, uint64_t paddr) {
    stream_state_t &st = stream_state[set];
    int8_t delta = 0;
    if(st.last_addr)
        delta = (int8_t)((paddr - st.last_addr) >> 6); // block granularity
    st.deltas[st.idx % STREAM_WINDOW] = delta;
    st.idx++;
    st.last_addr = paddr;
    int pos=0, neg=0;
    for(uint8_t i=0;i<STREAM_WINDOW;i++) {
        if(st.deltas[i]==1) pos++;
        else if(st.deltas[i]==-1) neg++;
    }
    if(pos >= STREAM_DELTA_THRESHOLD || neg >= STREAM_DELTA_THRESHOLD)
        st.stream_flag = 1;
    else
        st.stream_flag = 0;
}

// Initialize replacement state
void InitReplacementState() {
    for(uint32_t s=0; s<LLC_SETS; s++) {
        for(uint32_t w=0; w<LLC_WAYS; w++) {
            blocks[s][w] = {RRPV_MAX, 0}; // RRPV, dead_ctr
        }
        stream_state[s] = {0, {0}, 0, 0};
    }
    global_decay_ctr = 0;
}

// Find victim in the set (standard RRIP: evict highest RRPV, else increment RRPVs until found)
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Prefer blocks predicted dead (dead_ctr saturated)
    for(uint32_t w=0; w<LLC_WAYS; w++)
        if(blocks[set][w].dead_ctr == DEAD_MAX)
            return w;
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
    // Streaming detector
    update_stream_detector(set, paddr);

    // Dead-block decay (periodic, global)
    global_decay_ctr++;
    if(global_decay_ctr % DECAY_PERIOD == 0) {
        for(uint32_t s=0; s<LLC_SETS; s++)
            for(uint32_t w=0; w<LLC_WAYS; w++)
                if(blocks[s][w].dead_ctr > 0)
                    blocks[s][w].dead_ctr--;
    }

    if(hit) {
        // On hit: set block to MRU, reset dead_ctr
        blocks[set][way].rrpv = MRU_INSERT;
        blocks[set][way].dead_ctr = 0;
        return;
    }

    // On fill/replace: increment dead_ctr of victim block
    if(blocks[set][way].dead_ctr < DEAD_MAX)
        blocks[set][way].dead_ctr++;

    // Decide insertion RRPV
    uint8_t ins_rrpv = MRU_INSERT;
    // If streaming detected, insert at distant RRPV
    if(stream_state[set].stream_flag)
        ins_rrpv = DISTANT_INSERT;
    // If dead-block prediction saturated, insert at distant RRPV
    else if(blocks[set][way].dead_ctr == DEAD_MAX)
        ins_rrpv = DISTANT_INSERT;

    blocks[set][way].rrpv = ins_rrpv;
    blocks[set][way].dead_ctr = 0;
}

// Print end-of-simulation statistics
void PrintStats() {
    // Dead-block histogram
    int dead = 0, live = 0;
    for(uint32_t s=0; s<LLC_SETS; s++)
        for(uint32_t w=0; w<LLC_WAYS; w++)
            if(blocks[s][w].dead_ctr == DEAD_MAX) dead++;
            else live++;
    std::cout << "DBRIP-SD: Dead blocks = " << dead << ", Live blocks = " << live << std::endl;
    // Streaming set summary
    int streaming_sets = 0;
    for(uint32_t s=0; s<LLC_SETS; s++)
        if(stream_state[s].stream_flag)
            streaming_sets++;
    std::cout << "DBRIP-SD: Streaming sets = " << streaming_sets << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // No periodic stats needed
}