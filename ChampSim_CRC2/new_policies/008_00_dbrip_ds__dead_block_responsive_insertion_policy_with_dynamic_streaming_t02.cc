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
#define LRU_INSERT RRPV_MAX

// Dead-block predictor
#define DEAD_BITS 2
#define DEAD_MAX ((1<<DEAD_BITS)-1)
#define DEAD_THRESHOLD 2 // >=2 means likely dead

// Streaming detector
#define STREAM_WINDOW 8
#define STREAM_DELTA_THRESHOLD 6 // must see monotonic deltas in N out of last 8 fills

// Periodic decay
#define DECAY_PERIOD 4096

struct block_state_t {
    uint8_t rrpv;      // 2 bits: RRIP value
    uint8_t dead_cnt;  // 2 bits: dead-block counter
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

uint64_t global_access = 0;

// Utility: streaming detector
void update_stream_detector(uint32_t set, uint64_t paddr) {
    stream_state_t &st = stream_state[set];
    int8_t delta = 0;
    if(st.last_addr)
        delta = (int8_t)((paddr - st.last_addr) >> 6); // block granularity
    st.deltas[st.idx % STREAM_WINDOW] = delta;
    st.idx++;
    st.last_addr = paddr;
    // Check for monotonic deltas: majority of window must be all +1 or all -1
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
            blocks[s][w] = {RRPV_MAX, 0}; // RRPV, dead_cnt
        }
        stream_state[s] = {0, {0}, 0, 0};
    }
    global_access = 0;
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
    // Streaming sets: prefer to evict blocks with high dead_cnt
    if(stream_state[set].stream_flag) {
        for(uint32_t w=0; w<LLC_WAYS; w++)
            if(blocks[set][w].dead_cnt >= DEAD_THRESHOLD)
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
    global_access++;

    // Streaming detector
    update_stream_detector(set, paddr);

    // Periodic decay of dead_cnt (every DECAY_PERIOD accesses)
    if((global_access & (DECAY_PERIOD-1)) == 0) {
        for(uint32_t s=0; s<LLC_SETS; s++)
            for(uint32_t w=0; w<LLC_WAYS; w++)
                if(blocks[s][w].dead_cnt > 0)
                    blocks[s][w].dead_cnt--;
    }

    // On hit: set block to MRU, reset dead_cnt
    if(hit) {
        blocks[set][way].rrpv = MRU_INSERT;
        blocks[set][way].dead_cnt = 0;
        return;
    }

    // On fill/replace: increment dead_cnt for victim block
    if(blocks[set][way].dead_cnt < DEAD_MAX)
        blocks[set][way].dead_cnt++;

    // Decide insertion RRPV
    uint8_t ins_rrpv = MRU_INSERT;
    if(stream_state[set].stream_flag) {
        // Streaming: insert at LRU, or bypass if victim was dead
        if(blocks[set][way].dead_cnt >= DEAD_THRESHOLD)
            ins_rrpv = LRU_INSERT; // streaming + dead: aggressive eviction
        else
            ins_rrpv = RRPV_MAX-1; // streaming but not dead: slightly less aggressive
    } else {
        // Non-streaming: dead-block responsive
        if(blocks[set][way].dead_cnt >= DEAD_THRESHOLD)
            ins_rrpv = LRU_INSERT; // likely dead, insert at LRU
        else
            ins_rrpv = MRU_INSERT; // likely reused, insert at MRU
    }

    // Insert block
    blocks[set][way].rrpv = ins_rrpv;
    blocks[set][way].dead_cnt = 0;
}

// Print end-of-simulation statistics
void PrintStats() {
    int streaming_sets = 0, dead_blocks = 0, reused_blocks = 0;
    for(uint32_t s=0; s<LLC_SETS; s++) {
        if(stream_state[s].stream_flag)
            streaming_sets++;
        for(uint32_t w=0; w<LLC_WAYS; w++) {
            if(blocks[s][w].dead_cnt >= DEAD_THRESHOLD)
                dead_blocks++;
            else
                reused_blocks++;
        }
    }
    std::cout << "DBRIP-DS: Streaming sets = " << streaming_sets << std::endl;
    std::cout << "DBRIP-DS: Dead blocks = " << dead_blocks << ", Reused blocks = " << reused_blocks << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // No periodic stats needed
}