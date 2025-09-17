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
#define SHIP_SIG_BITS 5      // 5 bits per-block, 32-entry SHiP table
#define SHIP_TABLE_SIZE 128  // 128-entry global table (indexed by signature)
#define SHIP_CTR_BITS 2      // 2-bit outcome counter per entry

// Streaming detector
#define STREAM_HIST_LEN 4
#define STREAM_DELTA_THR 3

struct block_state_t {
    uint8_t rrpv : 2;
    uint8_t sig  : SHIP_SIG_BITS;
};

std::vector<std::vector<block_state_t>> blocks(LLC_SETS, std::vector<block_state_t>(LLC_WAYS));

// SHiP table: 128 entries, 2b counters
std::vector<uint8_t> SHIP_ctr(SHIP_TABLE_SIZE, 1); // init at mid-value

// Streaming detector state per set
struct stream_set_t {
    uint64_t prev_addr;
    int32_t deltas[STREAM_HIST_LEN];
    int ptr;
    bool streaming;
};
std::vector<stream_set_t> stream_sets(LLC_SETS);

// Utility: get PC signature
inline uint8_t get_signature(uint64_t PC) {
    // CRC32 folded to 5 bits for per-block tag, 7 bits for global table
    uint32_t crc = champsim_crc2(PC, 0);
    return (crc & ((1<<SHIP_SIG_BITS)-1));
}
inline uint8_t get_table_idx(uint64_t PC) {
    uint32_t crc = champsim_crc2(PC, 0);
    return (crc & (SHIP_TABLE_SIZE-1));
}

// Streaming detection logic
inline void update_streaming(uint32_t set, uint64_t paddr) {
    stream_set_t &st = stream_sets[set];
    if (st.prev_addr != 0) {
        int32_t delta = (int32_t)(paddr - st.prev_addr);
        st.deltas[st.ptr] = delta;
        st.ptr = (st.ptr + 1) % STREAM_HIST_LEN;
        // Count matching deltas
        int cnt = 0;
        int32_t ref = st.deltas[(st.ptr+STREAM_HIST_LEN-1)%STREAM_HIST_LEN];
        for(int i=0;i<STREAM_HIST_LEN;i++) if(st.deltas[i]==ref) cnt++;
        st.streaming = (cnt >= STREAM_DELTA_THR);
    }
    st.prev_addr = paddr;
}

void InitReplacementState() {
    for(uint32_t s=0; s<LLC_SETS; s++)
        for(uint32_t w=0; w<LLC_WAYS; w++)
            blocks[s][w] = {RRPV_MAX, 0};

    std::fill(SHIP_ctr.begin(), SHIP_ctr.end(), 1);
    for(uint32_t s=0; s<LLC_SETS; s++) {
        stream_sets[s].prev_addr = 0;
        memset(stream_sets[s].deltas, 0, sizeof(stream_sets[s].deltas));
        stream_sets[s].ptr = 0;
        stream_sets[s].streaming = false;
    }
}

// Find victim: highest RRPV, LRU among those
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
        // Increment all RRPVs
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
    update_streaming(set, paddr);
    uint8_t sig = get_signature(PC);
    uint8_t idx = get_table_idx(PC);

    if(hit) {
        blocks[set][way].rrpv = 0;
        // On hit, PC seen to have reuse
        if(SHIP_ctr[idx] < (1<<SHIP_CTR_BITS)-1)
            SHIP_ctr[idx]++;
    } else {
        // On fill / replacement
        bool streaming = stream_sets[set].streaming;
        if(streaming) {
            // Bypass: do not insert
            blocks[set][way].rrpv = RRPV_MAX;
            blocks[set][way].sig = sig;
        } else {
            // Use SHiP outcome to set insertion depth
            if(SHIP_ctr[idx] >= ((1<<SHIP_CTR_BITS)/2))
                blocks[set][way].rrpv = 1; // favored for retention
            else
                blocks[set][way].rrpv = RRPV_MAX-1; // distant
            blocks[set][way].sig = sig;
        }
        // On eviction: update SHiP outcome if no reuse
        // (victim_addr is valid only if block was present)
        if(blocks[set][way].rrpv == RRPV_MAX) {
            uint8_t evict_sig = blocks[set][way].sig;
            uint8_t evict_idx = evict_sig; // if table is indexed by PC signature
            if(SHIP_ctr[evict_idx] > 0)
                SHIP_ctr[evict_idx]--;
        }
    }
}

void PrintStats() {
    int reusable=0;
    for(uint32_t i=0; i<SHIP_TABLE_SIZE; i++)
        if(SHIP_ctr[i] >= ((1<<SHIP_CTR_BITS)/2)) reusable++;
    std::cout << "SRSB: SHiP table reusable count = " << reusable << "/" << SHIP_TABLE_SIZE << std::endl;
    int streaming_sets=0;
    for(uint32_t s=0; s<LLC_SETS; s++)
        if(stream_sets[s].streaming) streaming_sets++;
    std::cout << "SRSB: Streaming sets flagged = " << streaming_sets << "/" << LLC_SETS << std::endl;
}

void PrintStats_Heartbeat() {
    // Optional: print periodic SHiP stats or streaming set count if desired
}