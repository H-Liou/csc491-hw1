#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// RRIP metadata: 2 bits/block
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// Streaming detector: 3 bits/set
struct StreamSet {
    uint64_t last_addr;
    uint8_t stride_count; // up to 3
    uint8_t streaming;    // 1 if streaming detected
    uint8_t window;       // streaming window countdown
};
StreamSet stream_sets[LLC_SETS];

// DRRIP set-dueling: 64 leader sets
const uint32_t NUM_LEADER_SETS = 64;
uint32_t leader_sets[NUM_LEADER_SETS];
uint8_t leader_type[NUM_LEADER_SETS]; // 0: SRRIP, 1: BRRIP

// DRRIP PSEL: 10 bits
uint16_t PSEL = 512; // range 0–1023, init mid

// RRIP constants
const uint8_t RRIP_MAX = 3;
const uint8_t RRIP_MRU = 0;
const uint8_t RRIP_DISTANT = 2;

// Streaming window length
const uint8_t STREAM_WIN = 8;

// Helper: assign leader sets evenly
void InitLeaderSets() {
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i) {
        leader_sets[i] = (LLC_SETS / NUM_LEADER_SETS) * i;
        leader_type[i] = (i < NUM_LEADER_SETS / 2) ? 0 : 1; // half SRRIP, half BRRIP
    }
}

// Initialize replacement state
void InitReplacementState() {
    memset(rrpv, RRIP_MAX, sizeof(rrpv));
    memset(stream_sets, 0, sizeof(stream_sets));
    InitLeaderSets();
    PSEL = 512;
}

// Check if set is a leader set, and get its type
int get_leader_type(uint32_t set) {
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i)
        if (leader_sets[i] == set)
            return leader_type[i];
    return -1; // not a leader set
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
    // Streaming: if active, always evict block with RRPV==RRIP_MAX
    if (stream_sets[set].streaming && stream_sets[set].window > 0) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == RRIP_MAX)
                return way;
        // If none, increment RRPV and retry
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] < RRIP_MAX)
                rrpv[set][way]++;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == RRIP_MAX)
                return way;
        return 0;
    }

    // Standard RRIP victim selection
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (rrpv[set][way] == RRIP_MAX)
            return way;
    // If none, increment RRPV and retry
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (rrpv[set][way] < RRIP_MAX)
            rrpv[set][way]++;
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (rrpv[set][way] == RRIP_MAX)
            return way;
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
    // --- Streaming detector ---
    StreamSet &ss = stream_sets[set];
    uint64_t cur_addr = paddr >> 6; // cache line granularity
    int64_t stride = cur_addr - ss.last_addr;
    if (ss.last_addr != 0 && (stride == 1 || stride == -1)) {
        if (ss.stride_count < 3) ss.stride_count++;
        if (ss.stride_count == 3 && !ss.streaming) {
            ss.streaming = 1;
            ss.window = STREAM_WIN;
        }
    } else {
        ss.stride_count = 0;
        ss.streaming = 0;
        ss.window = 0;
    }
    ss.last_addr = cur_addr;
    if (ss.streaming && ss.window > 0)
        ss.window--;

    // --- RRIP update ---
    if (hit) {
        rrpv[set][way] = RRIP_MRU;
        // DRRIP: update PSEL if leader set
        int lt = get_leader_type(set);
        if (lt == 0 && PSEL < 1023) PSEL++; // SRRIP leader: increment
        if (lt == 1 && PSEL > 0)    PSEL--; // BRRIP leader: decrement
    } else {
        // --- Insertion policy ---
        uint8_t ins_rrpv;
        if (ss.streaming && ss.window > 0) {
            // Streaming detected: insert at RRIP_MAX (bypass)
            ins_rrpv = RRIP_MAX;
        } else {
            int lt = get_leader_type(set);
            if (lt == 0) { // SRRIP leader
                ins_rrpv = RRIP_DISTANT;
            } else if (lt == 1) { // BRRIP leader
                ins_rrpv = (rand() % 32 == 0) ? RRIP_DISTANT : RRIP_MAX; // 1/32 near, else far
            } else {
                // Follower: use PSEL to choose
                if (PSEL >= 512) { // SRRIP
                    ins_rrpv = RRIP_DISTANT;
                } else { // BRRIP
                    ins_rrpv = (rand() % 32 == 0) ? RRIP_DISTANT : RRIP_MAX;
                }
            }
        }
        rrpv[set][way] = ins_rrpv;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    // Streaming set count
    uint64_t streaming_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (stream_sets[s].streaming)
            streaming_sets++;
    std::cout << "DRRIP-SB: Streaming sets at end: " << streaming_sets << std::endl;
    // PSEL value
    std::cout << "DRRIP-SB: PSEL at end: " << PSEL << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Optionally print streaming set count or PSEL
}