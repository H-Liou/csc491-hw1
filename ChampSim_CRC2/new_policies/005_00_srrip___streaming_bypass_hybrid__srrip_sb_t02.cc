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

// Streaming detector parameters
#define STREAM_WIN 4 // window size for delta history
#define STREAM_THRESH 3 // threshold for streaming detection

// Per-block state
struct block_state_t {
    uint8_t rrpv; // 2b
};

// Per-set streaming detector: last N address deltas, 2b streaming flag
struct set_stream_t {
    uint64_t last_addr;
    int64_t deltas[STREAM_WIN];
    uint8_t idx;
    uint8_t streaming; // 2b: 0=not streaming, 1=streaming
};

std::vector<std::vector<block_state_t>> blocks(LLC_SETS, std::vector<block_state_t>(LLC_WAYS));
std::vector<set_stream_t> stream_state(LLC_SETS);

// Utility: update streaming detector for a set
void update_streaming(uint32_t set, uint64_t paddr) {
    set_stream_t &st = stream_state[set];
    int64_t delta = paddr - st.last_addr;
    st.last_addr = paddr;
    st.deltas[st.idx] = delta;
    st.idx = (st.idx + 1) % STREAM_WIN;

    // Check for monotonic or highly variable deltas
    int monotonic = 1;
    int variable = 0;
    for(int i=1; i<STREAM_WIN; i++) {
        if(st.deltas[i] != st.deltas[0]) variable++;
        if((st.deltas[i] > 0) != (st.deltas[0] > 0)) monotonic = 0;
    }
    // Streaming if all deltas same sign and at least STREAM_THRESH are variable
    if(monotonic && variable >= STREAM_THRESH)
        st.streaming = 1;
    else
        st.streaming = 0;
}

void InitReplacementState() {
    for(uint32_t s=0; s<LLC_SETS; s++) {
        for(uint32_t w=0; w<LLC_WAYS; w++)
            blocks[s][w].rrpv = RRPV_MAX; // distant
        stream_state[s].last_addr = 0;
        std::memset(stream_state[s].deltas, 0, sizeof(stream_state[s].deltas));
        stream_state[s].idx = 0;
        stream_state[s].streaming = 0;
    }
}

// Victim selection: highest RRPV
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Find block with RRPV==RRPV_MAX (oldest)
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
    // Update streaming detector
    update_streaming(set, paddr);

    // On hit: reset RRPV
    if(hit) {
        blocks[set][way].rrpv = 0;
        return;
    }

    // On fill/replace: streaming-aware insertion
    if(stream_state[set].streaming) {
        // Streaming detected: bypass with 1/2 probability, else insert at distant
        if(rand()%2 == 0) {
            blocks[set][way].rrpv = RRPV_MAX; // distant
        } else {
            // Bypass: set RRPV to max so it is evicted soon
            blocks[set][way].rrpv = RRPV_MAX;
        }
    } else {
        // Not streaming: insert at MRU
        blocks[set][way].rrpv = 0;
    }
}

void PrintStats() {
    int streaming_sets = 0;
    for(uint32_t s=0; s<LLC_SETS; s++)
        if(stream_state[s].streaming) streaming_sets++;
    std::cout << "SRRIP-SB: Streaming sets detected = " << streaming_sets << " / " << LLC_SETS << std::endl;
}

void PrintStats_Heartbeat() {
    // No periodic stats needed
}