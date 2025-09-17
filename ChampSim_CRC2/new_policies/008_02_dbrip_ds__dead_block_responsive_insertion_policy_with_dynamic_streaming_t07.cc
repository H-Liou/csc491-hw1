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
#define RRPV_MAX ((1 << RRPV_BITS) - 1)
#define SRRIP_INSERT 2
#define BRRIP_INSERT 3
#define MRU_INSERT 0

// Dead-block predictor
#define DEAD_BITS 2
#define DEAD_MAX ((1 << DEAD_BITS) - 1)
#define DEAD_THRESHOLD 2 // If counter >= threshold, considered dead

// Streaming detector
#define STREAM_WINDOW 8
#define STREAM_DELTA_THRESHOLD 6

// Metadata per block
struct block_state_t {
    uint8_t rrpv; // 2 bits: RRIP value
    uint8_t dead; // 2 bits: dead-block counter
};

// Per-set streaming detector
struct stream_state_t {
    uint64_t last_addr;
    int8_t deltas[STREAM_WINDOW];
    uint8_t idx;
    uint8_t stream_flag;
};

std::vector<std::vector<block_state_t>> blocks(LLC_SETS, std::vector<block_state_t>(LLC_WAYS));
std::vector<stream_state_t> stream_state(LLC_SETS);

// Periodic decay for dead-block counters
uint64_t global_fill_count = 0;
#define DECAY_PERIOD 4096

void update_stream_detector(uint32_t set, uint64_t paddr) {
    stream_state_t &st = stream_state[set];
    int8_t delta = 0;
    if (st.last_addr)
        delta = (int8_t)((paddr - st.last_addr) >> 6);
    st.deltas[st.idx % STREAM_WINDOW] = delta;
    st.idx++;
    st.last_addr = paddr;

    int pos = 0, neg = 0;
    for (uint8_t i = 0; i < STREAM_WINDOW; i++) {
        if (st.deltas[i] == 1) pos++;
        else if (st.deltas[i] == -1) neg++;
    }
    if (pos >= STREAM_DELTA_THRESHOLD || neg >= STREAM_DELTA_THRESHOLD)
        st.stream_flag = 1;
    else
        st.stream_flag = 0;
}

void decay_dead_counters() {
    // Decay all dead-block counters periodically
    for (uint32_t s = 0; s < LLC_SETS; s++)
        for (uint32_t w = 0; w < LLC_WAYS; w++)
            if (blocks[s][w].dead > 0)
                blocks[s][w].dead--;
}

// Initialize replacement state
void InitReplacementState() {
    for (uint32_t s = 0; s < LLC_SETS; s++) {
        for (uint32_t w = 0; w < LLC_WAYS; w++)
            blocks[s][w] = {RRPV_MAX, 0};
        stream_state[s] = {0, {0}, 0, 0};
    }
    global_fill_count = 0;
}

// Find victim in the set (standard RRIP)
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    while (true) {
        for (uint32_t w = 0; w < LLC_WAYS; w++)
            if (blocks[set][w].rrpv == RRPV_MAX)
                return w;
        for (uint32_t w = 0; w < LLC_WAYS; w++)
            if (blocks[set][w].rrpv < RRPV_MAX)
                blocks[set][w].rrpv++;
    }
    // Should never reach here
    return 0;
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
    update_stream_detector(set, paddr);

    // Decay dead-block counters every DECAY_PERIOD fills
    global_fill_count++;
    if (global_fill_count % DECAY_PERIOD == 0)
        decay_dead_counters();

    if (hit) {
        // On hit, set block to MRU and clear dead-block counter
        blocks[set][way].rrpv = MRU_INSERT;
        blocks[set][way].dead = 0;
        return;
    }

    // On replacement/fill, increment dead-block counter for victim
    if (blocks[set][way].dead < DEAD_MAX)
        blocks[set][way].dead++;

    // Streaming detected: favor BRRIP insertion for all except reusable blocks
    if (stream_state[set].stream_flag) {
        if (blocks[set][way].dead >= DEAD_THRESHOLD) {
            // If predicted dead, insert at distant RRPV or consider bypass (do not retain)
            blocks[set][way].rrpv = BRRIP_INSERT;
        } else {
            // If recently reused, retain at MRU
            blocks[set][way].rrpv = MRU_INSERT;
        }
    } else {
        // No streaming: insert based on dead-block prediction
        if (blocks[set][way].dead >= DEAD_THRESHOLD)
            blocks[set][way].rrpv = SRRIP_INSERT;
        else
            blocks[set][way].rrpv = MRU_INSERT;
    }
    // Reset dead-block counter on fill
    blocks[set][way].dead = 0;
}

// Print end-of-simulation statistics
void PrintStats() {
    int dead_lines = 0, live_lines = 0;
    for (uint32_t s = 0; s < LLC_SETS; s++)
        for (uint32_t w = 0; w < LLC_WAYS; w++)
            if (blocks[s][w].dead >= DEAD_THRESHOLD)
                dead_lines++;
            else
                live_lines++;
    std::cout << "DBRIP-DS: Dead lines = " << dead_lines << ", Live lines = " << live_lines << std::endl;

    int streaming_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; s++)
        if (stream_state[s].stream_flag)
            streaming_sets++;
    std::cout << "DBRIP-DS: Streaming sets = " << streaming_sets << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // No periodic stats needed
}