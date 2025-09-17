#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- Metadata structures ---
// 2 bits/line: RRPV
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// 4 bits/line: PC signature
uint8_t pc_sig[LLC_SETS][LLC_WAYS];

// SHiP table: 1K entries, 4 bits/counter
#define SHIP_TABLE_SIZE 1024
uint8_t ship_table[SHIP_TABLE_SIZE];

// DIP set-dueling: 32 leader sets, 10-bit PSEL
#define NUM_LEADER_SETS 32
uint8_t is_lip_leader[LLC_SETS]; // 1 if LIP leader, 2 if BIP leader, 0 otherwise
uint16_t psel; // 10 bits

// Streaming detector: per-set last address stride (8 bits/set), 2 bits/set stream score
int8_t last_stride[LLC_SETS];
uint8_t stream_score[LLC_SETS];

// Helper: hash PC to 4 bits
inline uint8_t get_signature(uint64_t PC) {
    return (PC ^ (PC >> 11) ^ (PC >> 17)) & 0xF;
}

// Helper: hash signature to SHiP table index
inline uint16_t ship_index(uint8_t sig) {
    return sig ^ (sig >> 2);
}

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 2, sizeof(rrpv)); // Initialize to distant
    memset(pc_sig, 0, sizeof(pc_sig));
    memset(ship_table, 2, sizeof(ship_table)); // Neutral reuse
    memset(last_stride, 0, sizeof(last_stride));
    memset(stream_score, 0, sizeof(stream_score));
    memset(is_lip_leader, 0, sizeof(is_lip_leader));
    psel = 512; // Neutral

    // Assign leader sets: first 16 as LIP, next 16 as BIP
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i) {
        if (i < NUM_LEADER_SETS / 2)
            is_lip_leader[i] = 1;
        else
            is_lip_leader[i] = 2;
    }
}

// --- Victim selection: SRRIP ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Standard SRRIP: find block with RRPV==3
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (rrpv[set][way] == 3)
                return way;
        }
        // Increment all RRPVs
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
    uint8_t sig = get_signature(PC);
    uint16_t idx = ship_index(sig);

    // --- Streaming detector ---
    int8_t stride = 0;
    static uint64_t last_addr[LLC_SETS] = {0};
    if (last_addr[set] != 0)
        stride = (int8_t)((paddr >> 6) - (last_addr[set] >> 6)); // block granularity
    last_addr[set] = paddr;

    // Update stream_score: if stride matches last_stride, increment; else, reset
    if (stride == last_stride[set] && stride != 0) {
        if (stream_score[set] < 3) stream_score[set]++;
    } else {
        stream_score[set] = 0;
        last_stride[set] = stride;
    }
    bool is_streaming = (stream_score[set] >= 2);

    // --- SHiP update ---
    if (hit) {
        rrpv[set][way] = 0;
        if (ship_table[idx] < 15)
            ship_table[idx]++;
    } else {
        pc_sig[set][way] = sig;

        // --- DIP set-dueling: choose insertion depth ---
        uint8_t insert_rrpv = 2; // Default distant

        if (is_lip_leader[set] == 1) { // LIP leader: always insert at LRU
            insert_rrpv = 3;
        } else if (is_lip_leader[set] == 2) { // BIP leader: insert at LRU, but 1/32 at MRU
            static uint32_t bip_ctr = 0;
            if ((bip_ctr++ & 0x1F) == 0)
                insert_rrpv = 0;
            else
                insert_rrpv = 3;
        } else {
            // Non-leader: use PSEL to select LIP or BIP
            if (psel >= 512) { // Favor BIP
                static uint32_t bip_ctr = 0;
                if ((bip_ctr++ & 0x1F) == 0)
                    insert_rrpv = 0;
                else
                    insert_rrpv = 3;
            } else { // Favor LIP
                insert_rrpv = 3;
            }
        }

        // Streaming phase detected: bypass or distant insert
        if (is_streaming) {
            insert_rrpv = 3;
        } else {
            // SHiP signature: if high reuse, bias toward MRU
            if (ship_table[idx] >= 12)
                insert_rrpv = 0;
            else if (ship_table[idx] >= 8 && insert_rrpv > 1)
                insert_rrpv = 1;
        }

        rrpv[set][way] = insert_rrpv;
    }

    // On eviction: decay SHiP counter if not reused
    if (!hit) {
        uint8_t evict_sig = pc_sig[set][way];
        uint16_t evict_idx = ship_index(evict_sig);
        if (ship_table[evict_idx] > 0)
            ship_table[evict_idx]--;
    }

    // --- DIP set-dueling: update PSEL ---
    if (!hit) {
        if (is_lip_leader[set] == 1) { // LIP leader
            if (psel < 1023) psel++;
        } else if (is_lip_leader[set] == 2) { // BIP leader
            if (psel > 0) psel--;
        }
    }
}

// --- Stats ---
void PrintStats() {
    std::cout << "DSSH: SHiP table (reuse counters) summary:" << std::endl;
    int reused = 0, total = 0;
    for (int i = 0; i < SHIP_TABLE_SIZE; ++i) {
        if (ship_table[i] >= 12) reused++;
        total++;
    }
    std::cout << "High-reuse signatures: " << reused << " / " << total << std::endl;
    // Streaming summary
    int streaming_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (stream_score[s] >= 2) streaming_sets++;
    std::cout << "Streaming sets: " << streaming_sets << " / " << LLC_SETS << std::endl;
    std::cout << "PSEL value: " << psel << std::endl;
}

void PrintStats_Heartbeat() {
    // Print fraction of streaming sets
    int streaming_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (stream_score[s] >= 2) streaming_sets++;
    std::cout << "DSSH: Streaming sets: " << streaming_sets << " / " << LLC_SETS << " | PSEL: " << psel << std::endl;
}