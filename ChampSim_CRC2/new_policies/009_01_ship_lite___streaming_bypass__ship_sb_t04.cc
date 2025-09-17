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

// SHiP-lite signature
#define SIG_BITS 6
#define SIG_MASK ((1<<SIG_BITS)-1)
#define SHIP_TABLE_SIZE 4096 // 4K entries

// Outcome counter
#define OUTCOME_BITS 2
#define OUTCOME_MAX ((1<<OUTCOME_BITS)-1)
#define OUTCOME_THRESHOLD 2 // >=2 = frequent reuse

// Streaming detector
#define STREAM_WINDOW 8
#define STREAM_DELTA_THRESHOLD 6

struct block_state_t {
    uint8_t rrpv;      // 2 bits: RRIP value
    uint8_t sig;       // 6 bits: PC signature
};

std::vector<std::vector<block_state_t>> blocks(LLC_SETS, std::vector<block_state_t>(LLC_WAYS));

// SHiP outcome table: 2b counter per signature
std::vector<uint8_t> ship_table(SHIP_TABLE_SIZE, 0);

// Streaming detector: per-set
struct stream_state_t {
    uint64_t last_addr;
    int8_t deltas[STREAM_WINDOW];
    uint8_t idx;
    uint8_t stream_flag;
};
std::vector<stream_state_t> stream_state(LLC_SETS);

uint64_t global_access = 0;

// Utility: get signature from PC
inline uint16_t get_sig(uint64_t PC) {
    // Simple hash: lower SIG_BITS of PC XOR upper SIG_BITS
    return ((PC >> 2) ^ (PC >> 16)) & SIG_MASK;
}

// Streaming detector
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
            blocks[s][w] = {RRPV_MAX, 0}; // RRPV, sig
        }
        stream_state[s] = {0, {0}, 0, 0};
    }
    std::fill(ship_table.begin(), ship_table.end(), 0);
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

    uint16_t sig = get_sig(PC);

    // On hit: set block to MRU, update SHiP outcome
    if(hit) {
        blocks[set][way].rrpv = MRU_INSERT;
        blocks[set][way].sig = sig;
        // Update outcome counter (increment, saturate)
        if(ship_table[sig] < OUTCOME_MAX)
            ship_table[sig]++;
        return;
    }

    // On fill/replace: update SHiP outcome for victim
    uint8_t victim_sig = blocks[set][way].sig;
    if(ship_table[victim_sig] > 0)
        ship_table[victim_sig]--;

    // Streaming bypass: if set is streaming and signature is low-reuse, skip fill
    if(stream_state[set].stream_flag && ship_table[sig] < OUTCOME_THRESHOLD) {
        // Do not insert into cache (simulate bypass)
        blocks[set][way].rrpv = RRPV_MAX;
        blocks[set][way].sig = sig;
        return;
    }

    // Decide insertion RRPV based on SHiP outcome
    uint8_t ins_rrpv = (ship_table[sig] >= OUTCOME_THRESHOLD) ? MRU_INSERT : LRU_INSERT;
    blocks[set][way].rrpv = ins_rrpv;
    blocks[set][way].sig = sig;
}

// Print end-of-simulation statistics
void PrintStats() {
    int streaming_sets = 0, reused_sigs = 0, dead_sigs = 0;
    for(uint32_t s=0; s<LLC_SETS; s++)
        if(stream_state[s].stream_flag)
            streaming_sets++;
    for(uint32_t i=0; i<SHIP_TABLE_SIZE; i++) {
        if(ship_table[i] >= OUTCOME_THRESHOLD)
            reused_sigs++;
        else
            dead_sigs++;
    }
    std::cout << "SHiP-SB: Streaming sets = " << streaming_sets << std::endl;
    std::cout << "SHiP-SB: Reused signatures = " << reused_sigs << ", Dead signatures = " << dead_sigs << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // No periodic stats needed
}