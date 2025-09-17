#include <vector>
#include <cstdint>
#include <iostream>
#include <algorithm>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// SRRIP/BRRIP parameters
#define RRPV_BITS 2
#define RRPV_MAX ((1<<RRPV_BITS)-1)
#define SRRIP_INSERT 2   // Insert at RRPV=2
#define BRRIP_INSERT 3   // Insert at RRPV=3
#define SHIP_MRU_INSERT 0// Insert at RRPV=0

// Set-dueling
#define PSEL_BITS 10
#define PSEL_MAX ((1<<PSEL_BITS)-1)
#define NUM_LEADER_SETS 32
#define LEADER_SET_STRIDE (LLC_SETS/NUM_LEADER_SETS)

// SHiP-lite
#define SIG_BITS 6
#define SIG_ENTRIES (1<<SIG_BITS)
#define OUTCOME_BITS 2
#define OUTCOME_MAX ((1<<OUTCOME_BITS)-1)
#define SIG_MASK (SIG_ENTRIES-1)

// Streaming detector
#define STREAM_WINDOW 8
#define STREAM_DELTA_THRESHOLD 6 // must see monotonic deltas in N out of last 8 fills

struct block_state_t {
    uint8_t rrpv;     // 2 bits: RRIP value
    uint8_t sig;      // 6 bits: SHiP-lite signature
};

std::vector<std::vector<block_state_t>> blocks(LLC_SETS, std::vector<block_state_t>(LLC_WAYS));

// SHiP-lite signature table: outcome counters
std::vector<uint8_t> sig_table(SIG_ENTRIES, 1); // 2b per entry, weakly reused

// DIP set-dueling
std::vector<uint8_t> set_type(LLC_SETS, 0); // 0: follower, 1: SRRIP leader, 2: BRRIP leader
uint16_t PSEL = PSEL_MAX/2;

// Streaming detector: per-set
struct stream_state_t {
    uint64_t last_addr;
    int8_t deltas[STREAM_WINDOW];
    uint8_t idx;
    uint8_t stream_flag;
};
std::vector<stream_state_t> stream_state(LLC_SETS);

// Utility: assign leader sets
void assign_leader_sets() {
    for (uint32_t i = 0; i < NUM_LEADER_SETS; i++) {
        uint32_t s1 = i * LEADER_SET_STRIDE;
        uint32_t s2 = i * LEADER_SET_STRIDE + LEADER_SET_STRIDE/2;
        if (s1 < LLC_SETS) set_type[s1] = 1;  // SRRIP leader
        if (s2 < LLC_SETS) set_type[s2] = 2;  // BRRIP leader
    }
}

// Utility: compute signature from PC (6 bits, simple hash)
inline uint8_t get_sig(uint64_t PC) {
    return (uint8_t)((PC ^ (PC>>6) ^ (PC>>12)) & SIG_MASK);
}

// Streaming detector: update per-set state, mark streaming if monotonic deltas predominate
void update_stream_detector(uint32_t set, uint64_t paddr) {
    stream_state_t &st = stream_state[set];
    int8_t delta = 0;
    if(st.last_addr)
        delta = (int8_t)((paddr - st.last_addr) >> 6); // block granularity
    st.deltas[st.idx % STREAM_WINDOW] = delta;
    st.idx++;
    st.last_addr = paddr;
    // Check for monotonic deltas: majority of window must be all +1 or all -1
    int pos=0, neg=0, zero=0;
    for(uint8_t i=0;i<STREAM_WINDOW;i++) {
        if(st.deltas[i]==1) pos++;
        else if(st.deltas[i]==-1) neg++;
        else if(st.deltas[i]==0) zero++;
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
        set_type[s] = 0;
        stream_state[s] = {0, {0}, 0, 0};
    }
    std::fill(sig_table.begin(), sig_table.end(), 1);
    assign_leader_sets();
    PSEL = PSEL_MAX/2;
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
    // Search for block with RRPV==RRPV_MAX
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
    uint8_t sig = get_sig(PC);

    // Streaming detector
    update_stream_detector(set, paddr);

    // On hit: set block to RRPV=0 (MRU), mark signature reused
    if(hit) {
        blocks[set][way].rrpv = 0;
        blocks[set][way].sig = sig;
        // SHiP-lite: increment outcome for sig
        if(sig_table[sig] < OUTCOME_MAX)
            sig_table[sig]++;
        // DIP set-dueling: leaders update PSEL
        uint8_t stype = set_type[set];
        if(stype == 1 && PSEL < PSEL_MAX) PSEL++;
        else if(stype == 2 && PSEL > 0) PSEL--;
        return;
    }

    // On fill/replace: update previous block's outcome (dead if not reused)
    uint8_t victim_sig = blocks[set][way].sig;
    if(sig_table[victim_sig] > 0)
        sig_table[victim_sig]--;

    // Decide insertion RRPV
    uint8_t stype = set_type[set];
    uint8_t ins_rrpv = SRRIP_INSERT;
    if(stype == 1) {
        ins_rrpv = SRRIP_INSERT;
    } else if(stype == 2) {
        ins_rrpv = BRRIP_INSERT;
    } else {
        // Follower: use PSEL
        if(PSEL >= PSEL_MAX/2)
            ins_rrpv = SRRIP_INSERT;
        else
            ins_rrpv = BRRIP_INSERT;
    }

    // Streaming override: if streaming detected, force BRRIP insertion
    if(stream_state[set].stream_flag)
        ins_rrpv = BRRIP_INSERT;

    // SHiP-lite override: if signature shows reuse, insert at MRU
    if(sig_table[sig] >= (OUTCOME_MAX/2))
        ins_rrpv = SHIP_MRU_INSERT;

    // Insert block
    blocks[set][way].rrpv = ins_rrpv;
    blocks[set][way].sig = sig;
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "SRRIP-SD: Final PSEL value = " << PSEL << std::endl;
    // Signature reuse histogram
    int reused = 0, dead = 0;
    for(auto c : sig_table)
        if(c >= (OUTCOME_MAX/2)) reused++;
        else dead++;
    std::cout << "SRRIP-SD: Reused sigs = " << reused << ", Dead sigs = " << dead << std::endl;
    // Streaming set summary
    int streaming_sets = 0;
    for(uint32_t s=0; s<LLC_SETS; s++)
        if(stream_state[s].stream_flag)
            streaming_sets++;
    std::cout << "SRRIP-SD: Streaming sets = " << streaming_sets << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // No periodic stats needed
}