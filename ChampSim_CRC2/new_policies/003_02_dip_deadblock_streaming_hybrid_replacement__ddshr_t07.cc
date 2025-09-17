#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- DIP Leader Sets ---
#define NUM_LEADER_SETS 64
#define PSEL_MAX 1023  // 10 bits
uint16_t psel = PSEL_MAX / 2;
uint8_t leader_set_type[NUM_LEADER_SETS]; // 0: LIP, 1: BIP

// --- Dead-block bit (1 bit per line) ---
uint8_t dead_bit[LLC_SETS][LLC_WAYS]; // 0: alive, 1: dead

// --- 2-bit RRPV per line (SRRIP basis) ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// --- Streaming detector: 2 bits/set, stride, last_addr ---
int8_t last_stride[LLC_SETS];
uint64_t last_addr[LLC_SETS];
uint8_t stream_score[LLC_SETS]; // 0–3

// --- Helper: identify leader sets ---
inline bool is_leader_set(uint32_t set, uint8_t& type) {
    if (set % (LLC_SETS / NUM_LEADER_SETS) == 0) {
        uint8_t idx = set / (LLC_SETS / NUM_LEADER_SETS);
        type = leader_set_type[idx];
        return true;
    }
    return false;
}

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 2, sizeof(rrpv)); // Initialize to distant
    memset(dead_bit, 0, sizeof(dead_bit));
    memset(last_stride, 0, sizeof(last_stride));
    memset(last_addr, 0, sizeof(last_addr));
    memset(stream_score, 0, sizeof(stream_score));
    // Configure leader sets: alternate LIP/BIP
    for (uint8_t i = 0; i < NUM_LEADER_SETS; ++i)
        leader_set_type[i] = (i < NUM_LEADER_SETS / 2) ? 0 : 1; // 0: LIP, 1: BIP
    psel = PSEL_MAX / 2;
}

// --- Victim selection (SRRIP + dead-block override) ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Priority: dead-block
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (dead_bit[set][way]) return way;
    // Otherwise, standard SRRIP (RRPV==3)
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3) return way;
        // Increment all RRPVs
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] < 3) rrpv[set][way]++;
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
    // --- Streaming detection ---
    int8_t stride = 0;
    if (last_addr[set] != 0)
        stride = (int8_t)((paddr >> 6) - (last_addr[set] >> 6));
    last_addr[set] = paddr;
    if (stride == last_stride[set] && stride != 0) {
        if (stream_score[set] < 3) stream_score[set]++;
    } else {
        stream_score[set] = 0;
        last_stride[set] = stride;
    }
    bool is_streaming = (stream_score[set] >= 2);

    // --- DIP leader set logic ---
    uint8_t leader_type = 2; // invalid
    bool leader = is_leader_set(set, leader_type);

    // --- Dead-block update: periodic decay every 64K accesses ---
    static uint64_t access_counter = 0;
    access_counter++;
    if ((access_counter & 0xFFFF) == 0) { // every 64K accesses
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            for (uint32_t w = 0; w < LLC_WAYS; ++w)
                dead_bit[s][w] = 0; // reset all dead bits
    }

    // --- On hit: mark alive, set MRU ---
    if (hit) {
        rrpv[set][way] = 0;
        dead_bit[set][way] = 0;
        // DIP: update PSEL if in leader set
        if (leader) {
            if (leader_type == 0 && psel < PSEL_MAX) psel++; // LIP leader
            else if (leader_type == 1 && psel > 0) psel--; // BIP leader
        }
    }
    // --- On miss (insert) ---
    else {
        dead_bit[set][way] = 0;
        // Streaming: insert at distant, or bypass if streaming is strong
        if (is_streaming) {
            rrpv[set][way] = 3; // streaming: bypass (insert at LRU)
        }
        else {
            // DIP insertion selector (non-leader sets)
            if (!leader) {
                if (psel >= PSEL_MAX / 2) {
                    // LIP: insert at LRU (RRPV=3)
                    rrpv[set][way] = 3;
                } else {
                    // BIP: insert at LRU (RRPV=3) except 1/32 MRU (RRPV=0)
                    static uint32_t bip_ctr = 0;
                    bip_ctr++;
                    if ((bip_ctr & 31) == 0)
                        rrpv[set][way] = 0;
                    else
                        rrpv[set][way] = 3;
                }
            }
            // Leader sets: forced LIP or BIP
            else {
                if (leader_type == 0)
                    rrpv[set][way] = 3; // LIP
                else {
                    static uint32_t bip_ctr2 = 0;
                    bip_ctr2++;
                    if ((bip_ctr2 & 31) == 0)
                        rrpv[set][way] = 0;
                    else
                        rrpv[set][way] = 3;
                }
            }
        }
    }

    // --- Dead-block prediction: if a line is evicted without a hit, mark it as dead ---
    if (!hit) {
        dead_bit[set][way] = 1;
    }
}

// --- Stats ---
void PrintStats() {
    std::cout << "DDSHR: PSEL=" << psel << std::endl;
    // Dead-block summary
    int dead_lines = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        for (uint32_t w = 0; w < LLC_WAYS; ++w)
            if (dead_bit[s][w]) dead_lines++;
    std::cout << "Dead lines: " << dead_lines << " / " << (LLC_SETS * LLC_WAYS) << std::endl;
    int streaming_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (stream_score[s] >= 2) streaming_sets++;
    std::cout << "Streaming sets: " << streaming_sets << " / " << LLC_SETS << std::endl;
}

void PrintStats_Heartbeat() {
    int streaming_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (stream_score[s] >= 2) streaming_sets++;
    std::cout << "DDSHR: Streaming sets: " << streaming_sets << std::endl;
}