#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// RRIP parameters
#define RRPV_BITS 2
#define RRPV_MAX ((1<<RRPV_BITS)-1)
#define RRPV_MRU 0
#define RRPV_DISTANT RRPV_MAX

// Streaming detector parameters
#define STREAM_CNT_BITS 2
#define STREAM_CNT_MAX ((1<<STREAM_CNT_BITS)-1)
#define STREAM_DETECT_THRESH 2
#define DECAY_PERIOD 8192 // Decay counters every N fills

struct block_state_t {
    uint8_t rrpv;             // 2b
    uint8_t stream_cnt;       // 2b
    uint64_t last_addr;       // 8B (can be compressed if needed)
};

std::vector<std::vector<block_state_t>> blocks(LLC_SETS, std::vector<block_state_t>(LLC_WAYS));
uint64_t fill_count = 0;

// Initialize replacement state
void InitReplacementState() {
    for(uint32_t s=0; s<LLC_SETS; s++)
        for(uint32_t w=0; w<LLC_WAYS; w++)
            blocks[s][w] = {RRPV_DISTANT, 0, 0};
    fill_count = 0;
}

// Find victim in the set (highest RRPV)
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Find block with RRPV==RRPV_MAX
    for(uint32_t w=0; w<LLC_WAYS; w++)
        if(blocks[set][w].rrpv == RRPV_MAX)
            return w;
    // If none, increment all RRPVs and retry
    for(uint32_t w=0; w<LLC_WAYS; w++)
        if(blocks[set][w].rrpv < RRPV_MAX)
            blocks[set][w].rrpv++;
    // Second pass
    for(uint32_t w=0; w<LLC_WAYS; w++)
        if(blocks[set][w].rrpv == RRPV_MAX)
            return w;
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
    block_state_t &blk = blocks[set][way];

    // Streaming detection: compare address delta
    bool is_stream = false;
    if(hit) {
        uint64_t delta = (blk.last_addr) ? std::abs((int64_t)paddr - (int64_t)blk.last_addr) : 0;
        if(delta == 64 || delta == -64) { // Assume 64B line, monotonic stride
            if(blk.stream_cnt < STREAM_CNT_MAX) blk.stream_cnt++;
        } else if(blk.stream_cnt > 0) {
            blk.stream_cnt--;
        }
        blk.last_addr = paddr;
        // On hit: reset RRPV
        blk.rrpv = RRPV_MRU;
        return;
    }

    // On fill/replace: streaming counter
    is_stream = (blk.stream_cnt >= STREAM_DETECT_THRESH);

    // Periodic decay of streaming counters
    fill_count++;
    if(fill_count % DECAY_PERIOD == 0) {
        for(uint32_t s=0; s<LLC_SETS; s++)
            for(uint32_t w=0; w<LLC_WAYS; w++)
                if(blocks[s][w].stream_cnt > 0)
                    blocks[s][w].stream_cnt--;
    }

    // Streaming bypass: if streaming detected, do not insert (simulate by setting RRPV_MAX)
    uint8_t ins_rrpv = RRPV_MRU;
    if(is_stream) {
        ins_rrpv = RRPV_DISTANT; // Insert at distant, or optionally bypass (not inserting at all)
    }

    // Insert block
    blk.rrpv = ins_rrpv;
    blk.stream_cnt = 0;
    blk.last_addr = paddr;
}

// Print end-of-simulation statistics
void PrintStats() {
    int stream_blocks = 0, non_stream_blocks = 0;
    for(uint32_t s=0; s<LLC_SETS; s++)
        for(uint32_t w=0; w<LLC_WAYS; w++)
            if(blocks[s][w].stream_cnt >= STREAM_DETECT_THRESH)
                stream_blocks++;
            else
                non_stream_blocks++;
    std::cout << "SSBH: Stream blocks = " << stream_blocks
              << ", Non-stream blocks = " << non_stream_blocks << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // No periodic stats needed
}