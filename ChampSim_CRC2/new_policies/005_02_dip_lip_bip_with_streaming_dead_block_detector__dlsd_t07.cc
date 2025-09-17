#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- DIP set-dueling ---
uint16_t PSEL = 512; // 10 bits, neutral value
const uint32_t NUM_LEADER_SETS = 64;
uint32_t leader_sets_LIP[NUM_LEADER_SETS];
uint32_t leader_sets_BIP[NUM_LEADER_SETS];

// --- Per-line metadata ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];     // 2 bits/line
uint8_t reuse[LLC_SETS][LLC_WAYS];    // 2 bits/line

// --- Streaming detector ---
uint64_t last_addr[LLC_SETS];
int8_t last_stride[LLC_SETS];
uint8_t stream_score[LLC_SETS];       // 2 bits/set

// --- Helper: initialize leader sets randomly ---
void init_leader_sets() {
    // Pick NUM_LEADER_SETS out of LLC_SETS for each policy, disjoint sets
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i) {
        leader_sets_LIP[i] = i;
        leader_sets_BIP[i] = i + NUM_LEADER_SETS;
    }
}

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv));
    memset(reuse, 0, sizeof(reuse));
    memset(last_addr, 0, sizeof(last_addr));
    memset(last_stride, 0, sizeof(last_stride));
    memset(stream_score, 0, sizeof(stream_score));
    PSEL = 512;
    init_leader_sets();
}

// --- Check if set is leader for LIP or BIP ---
bool is_leader_LIP(uint32_t set) {
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i)
        if (leader_sets_LIP[i] == set) return true;
    return false;
}
bool is_leader_BIP(uint32_t set) {
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i)
        if (leader_sets_BIP[i] == set) return true;
    return false;
}

// --- Victim selection: SRRIP + dead-block bias ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Prefer dead blocks (reuse==0); if none, use SRRIP as fallback
    for (uint32_t way = 0; way < LLC_WAYS; ++way) {
        if (reuse[set][way] == 0)
            return way;
    }
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (rrpv[set][way] == 3)
                return way;
        }
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (rrpv[set][way] < 3)
                rrpv[set][way]++;
        }
    }
}

// --- Replacement state update ---
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
    int8_t stride = 0;
    if (last_addr[set] != 0)
        stride = (int8_t)((paddr >> 6) - (last_addr[set] >> 6)); // line granularity
    last_addr[set] = paddr;
    if (stride == last_stride[set] && stride != 0) {
        if (stream_score[set] < 3) stream_score[set]++;
    } else {
        stream_score[set] = 0;
        last_stride[set] = stride;
    }
    bool is_streaming = (stream_score[set] >= 2);

    // --- Dead-block reuse counter decay ---
    // Simple periodic decay: every 4096 fills
    static uint64_t global_fills = 0;
    global_fills++;
    if ((global_fills & 0xFFF) == 0) { // every 4096 fills
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            for (uint32_t w = 0; w < LLC_WAYS; ++w)
                if (reuse[s][w] > 0) reuse[s][w]--;
    }

    // --- On cache hit ---
    if (hit) {
        rrpv[set][way] = 0;
        if (reuse[set][way] < 3) reuse[set][way]++;
    } else {
        // --- Insertion policy selection: DIP set-dueling ---
        bool use_LIP = false, use_BIP = false;
        if (is_leader_LIP(set)) use_LIP = true;
        else if (is_leader_BIP(set)) use_BIP = true;
        else use_LIP = (PSEL >= 512); // Majority: LIP if PSEL high, else BIP

        // --- Streaming bypass/dead-block insertion ---
        if (is_streaming) {
            rrpv[set][way] = 3; // Insert at LRU
            reuse[set][way] = 0;
        } else if (use_LIP) {
            rrpv[set][way] = 3; // LIP: insert at LRU
            reuse[set][way] = 1;
        } else if (use_BIP) {
            // BIP: insert at MRU with low probability (1/32), else LRU
            static uint32_t fill_count = 0;
            fill_count++;
            if ((fill_count & 0x1F) == 0) {
                rrpv[set][way] = 0;
                reuse[set][way] = 2;
            } else {
                rrpv[set][way] = 3;
                reuse[set][way] = 1;
            }
        } else {
            // Follower sets: use majority DIP policy
            if (PSEL >= 512) {
                rrpv[set][way] = 3;
                reuse[set][way] = 1;
            } else {
                static uint32_t fill_count = 0;
                fill_count++;
                if ((fill_count & 0x1F) == 0) {
                    rrpv[set][way] = 0;
                    reuse[set][way] = 2;
                } else {
                    rrpv[set][way] = 3;
                    reuse[set][way] = 1;
                }
            }
        }
    }

    // --- DIP set-dueling PSEL update ---
    // On eviction, update PSEL depending on hit/miss in leader sets
    if (!hit && victim_addr) {
        if (is_leader_LIP(set) && PSEL < 1023) PSEL++;
        if (is_leader_BIP(set) && PSEL > 0) PSEL--;
        // On eviction, decay reuse counter
        reuse[set][way] = 0;
    }
}

// --- Stats ---
void PrintStats() {
    int streaming_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (stream_score[s] >= 2) streaming_sets++;
    std::cout << "DLSD: Streaming sets: " << streaming_sets << " / " << LLC_SETS << std::endl;
    std::cout << "DLSD: PSEL=" << PSEL << " (policy: " << ((PSEL >= 512) ? "LIP" : "BIP") << ")" << std::endl;
    int dead_blocks = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        for (uint32_t w = 0; w < LLC_WAYS; ++w)
            if (reuse[s][w] == 0) dead_blocks++;
    std::cout << "DLSD: Dead blocks: " << dead_blocks << " / " << (LLC_SETS * LLC_WAYS) << std::endl;
}

void PrintStats_Heartbeat() {
    int streaming_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (stream_score[s] >= 2) streaming_sets++;
    std::cout << "DLSD: Streaming sets: " << streaming_sets << std::endl;
    std::cout << "DLSD: PSEL=" << PSEL << std::endl;
}