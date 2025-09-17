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

// DIP parameters
#define LEADER_SETS 64
#define PSEL_BITS 10
#define PSEL_MAX ((1<<PSEL_BITS)-1)
#define BIP_PROB 32 // Insert at MRU 1/32 of time for BIP

// Streaming detector parameters
#define STREAM_WIN 4
#define STREAM_DELTA_THRESHOLD 3 // Require 3/4 deltas to match

struct block_state_t {
    uint8_t rrpv; // 2 bits: RRIP value
};

std::vector<std::vector<block_state_t>> blocks(LLC_SETS, std::vector<block_state_t>(LLC_WAYS));

// DIP: leader set assignment
std::vector<uint8_t> set_type(LLC_SETS, 0); // 0: follower, 1: LIP leader, 2: BIP leader
uint16_t psel = PSEL_MAX/2;

// Streaming detector: per-set window of recent address deltas
struct stream_state_t {
    uint64_t last_addr;
    int64_t deltas[STREAM_WIN];
    uint8_t ptr;
};
std::vector<stream_state_t> stream_info(LLC_SETS);

// Utility: assign leader sets (evenly spread)
void InitLeaderSets() {
    for (uint32_t i = 0; i < LEADER_SETS; i++) {
        set_type[i] = 1; // LIP leader
        set_type[LLC_SETS - 1 - i] = 2; // BIP leader
    }
    // Rest are followers (0)
}

// Initialize replacement state
void InitReplacementState() {
    for(uint32_t s=0; s<LLC_SETS; s++)
        for(uint32_t w=0; w<LLC_WAYS; w++)
            blocks[s][w] = {RRPV_MAX}; // LRU
    InitLeaderSets();
    psel = PSEL_MAX/2;
    for(uint32_t s=0; s<LLC_SETS; s++) {
        stream_info[s].last_addr = 0;
        std::fill(stream_info[s].deltas, stream_info[s].deltas+STREAM_WIN, 0);
        stream_info[s].ptr = 0;
    }
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
}

// Streaming detection: update window, return true if streaming detected
bool IsStreaming(uint32_t set, uint64_t paddr) {
    stream_state_t &st = stream_info[set];
    int64_t delta = int64_t(paddr) - int64_t(st.last_addr);
    if (st.last_addr != 0) {
        st.deltas[st.ptr] = delta;
        st.ptr = (st.ptr + 1) % STREAM_WIN;
    }
    st.last_addr = paddr;
    // Check if deltas are mostly equal and nonzero
    int64_t ref = st.deltas[0];
    if (ref == 0) return false;
    int match = 0;
    for (uint8_t i = 1; i < STREAM_WIN; i++)
        if (st.deltas[i] == ref)
            match++;
    return (match >= STREAM_DELTA_THRESHOLD);
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
    // On hit: set block to MRU
    if (hit) {
        blocks[set][way].rrpv = SRRIP_INSERT;
        return;
    }

    // Streaming detection: if streaming, insert at distant RRPV (bypass)
    bool streaming = IsStreaming(set, paddr);

    // DIP: choose insertion policy
    uint8_t ins_rrpv = SRRIP_INSERT; // default MRU
    if (set_type[set] == 1) {
        // LIP leader: always insert at LRU
        ins_rrpv = BRRIP_INSERT;
    } else if (set_type[set] == 2) {
        // BIP leader: insert at MRU 1/BIP_PROB times, else LRU
        static uint32_t bip_ctr = 0;
        if ((++bip_ctr % BIP_PROB) == 0)
            ins_rrpv = SRRIP_INSERT;
        else
            ins_rrpv = BRRIP_INSERT;
    } else {
        // Follower: use PSEL to choose
        if (psel >= (PSEL_MAX/2))
            ins_rrpv = BRRIP_INSERT; // LIP
        else
            ins_rrpv = SRRIP_INSERT; // BIP
    }

    // If streaming detected, override to distant RRPV
    if (streaming)
        ins_rrpv = BRRIP_INSERT;

    blocks[set][way].rrpv = ins_rrpv;

    // DIP: update PSEL on hits/misses in leader sets
    if (set_type[set] == 1) {
        // LIP leader
        if (hit && psel < PSEL_MAX)
            psel++;
        else if (!hit && psel > 0)
            psel--;
    } else if (set_type[set] == 2) {
        // BIP leader
        if (hit && psel > 0)
            psel--;
        else if (!hit && psel < PSEL_MAX)
            psel++;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "DIP-SD: PSEL=" << psel << std::endl;
    int streaming_sets = 0;
    for(uint32_t s=0; s<LLC_SETS; s++) {
        int64_t ref = stream_info[s].deltas[0];
        int match = 0;
        if (ref != 0)
            for (uint8_t i = 1; i < STREAM_WIN; i++)
                if (stream_info[s].deltas[i] == ref)
                    match++;
        if (match >= STREAM_DELTA_THRESHOLD)
            streaming_sets++;
    }
    std::cout << "DIP-SD: Streaming sets detected=" << streaming_sets << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // No periodic stats needed
}