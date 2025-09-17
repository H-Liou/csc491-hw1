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

// SHiP-lite signature table
#define SIGNATURE_BITS 6 // 64 entries per set
#define SIG_TABLE_SIZE (1<<SIGNATURE_BITS)
#define SIG_COUNTER_BITS 2
#define SIG_COUNTER_MAX ((1<<SIG_COUNTER_BITS)-1)
#define SIG_COUNTER_INIT 1 // neutral bias

// Streaming detector parameters
#define STREAM_WINDOW 4 // last 4 fills per set
#define STREAM_DELTA_THRESHOLD 3 // must see 3/4 monotonic deltas to trigger streaming

struct block_state_t {
    uint8_t rrpv; // 2 bits
    uint8_t signature; // 6 bits
};

std::vector<std::vector<block_state_t>> blocks(LLC_SETS, std::vector<block_state_t>(LLC_WAYS));

// SHiP-lite signature table: per set, 64 entries
std::vector<std::vector<uint8_t>> sig_table(LLC_SETS, std::vector<uint8_t>(SIG_TABLE_SIZE, SIG_COUNTER_INIT));

// DRRIP set-dueling
std::vector<uint8_t> is_srrip_leader(LLC_SETS, 0);
std::vector<uint8_t> is_brrip_leader(LLC_SETS, 0);
uint16_t psel = PSEL_MAX/2;

// Streaming detector per set: keep last 4 address deltas
std::vector<std::vector<int64_t>> stream_window(LLC_SETS, std::vector<int64_t>(STREAM_WINDOW, 0));
std::vector<uint8_t> stream_idx(LLC_SETS, 0);
std::vector<uint8_t> is_streaming(LLC_SETS, 0);

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
            blocks[s][w] = {RRPV_MAX, 0};
        }
        for(uint32_t i=0; i<SIG_TABLE_SIZE; i++)
            sig_table[s][i] = SIG_COUNTER_INIT;
        stream_idx[s] = 0;
        is_streaming[s] = 0;
        std::fill(stream_window[s].begin(), stream_window[s].end(), 0);
    }
    assign_leader_sets();
    psel = PSEL_MAX/2;
}

// Compute 6-bit PC signature
inline uint8_t get_signature(uint64_t PC) {
    return (PC ^ (PC >> SIGNATURE_BITS)) & (SIG_TABLE_SIZE-1);
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

// Update streaming detector window
void update_stream_window(uint32_t set, uint64_t paddr) {
    uint8_t idx = stream_idx[set];
    int64_t delta = 0;
    if(idx != 0)
        delta = paddr - stream_window[set][(idx-1) % STREAM_WINDOW];
    stream_window[set][idx] = paddr;
    stream_idx[set] = (idx+1) % STREAM_WINDOW;
    // If window full, check monotonicity
    if(idx == STREAM_WINDOW-1) {
        int monotonic = 0;
        for(uint8_t i=1; i<STREAM_WINDOW; i++) {
            int64_t d = stream_window[set][i] - stream_window[set][i-1];
            if(d == delta && delta != 0)
                monotonic++;
        }
        is_streaming[set] = (monotonic >= STREAM_DELTA_THRESHOLD) ? 1 : 0;
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
    // Streaming window update (for fill events)
    if(!hit)
        update_stream_window(set, paddr);

    // Get PC signature
    uint8_t sig = get_signature(PC);

    // On hit: set block to MRU, increment outcome counter
    if(hit) {
        blocks[set][way].rrpv = SRRIP_INSERT;
        blocks[set][way].signature = sig;
        // Increment SHiP-lite signature counter if not saturated
        if(sig_table[set][sig] < SIG_COUNTER_MAX)
            sig_table[set][sig]++;
        // Update PSEL for leader sets
        if(is_srrip_leader[set] && psel < PSEL_MAX)
            psel++;
        if(is_brrip_leader[set] && psel > 0)
            psel--;
        return;
    }

    // On fill/replace: insertion policy
    // If streaming detected in this set: bypass or insert at distant RRIP
    if(is_streaming[set]) {
        blocks[set][way].rrpv = RRPV_MAX; // streaming: insert at distant RRIP
        blocks[set][way].signature = sig;
        return;
    }

    // SHiP-lite: use PC signature table to bias insertion depth
    uint8_t ins_rrpv;
    if(sig_table[set][sig] >= SIG_COUNTER_MAX-1)
        ins_rrpv = SRRIP_INSERT; // frequent reuse: aggressive
    else if(sig_table[set][sig] == 0)
        ins_rrpv = BRRIP_INSERT; // poor reuse: conservative
    else {
        // DRRIP set-dueling for neutral signatures
        if(is_srrip_leader[set])
            ins_rrpv = SRRIP_INSERT;
        else if(is_brrip_leader[set])
            ins_rrpv = BRRIP_INSERT;
        else
            ins_rrpv = (psel >= PSEL_MAX/2) ? SRRIP_INSERT : BRRIP_INSERT;
    }
    blocks[set][way].rrpv = ins_rrpv;
    blocks[set][way].signature = sig;

    // On eviction: decay PC signature counter if not hit before eviction
    if(sig_table[set][sig] > 0)
        sig_table[set][sig]--;
}

// Print end-of-simulation statistics
void PrintStats() {
    size_t streaming_sets = 0;
    for(uint32_t s=0; s<LLC_SETS; s++)
        if(is_streaming[s]) streaming_sets++;
    std::cout << "SHiP-Lite+Streaming: Streaming sets: " << streaming_sets << "/" << LLC_SETS << std::endl;
    std::cout << "SHiP-Lite+Streaming: PSEL = " << psel << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Not implemented
}