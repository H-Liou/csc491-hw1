#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- DRRIP metadata ---
static uint8_t rrpv[LLC_SETS][LLC_WAYS]; // 2 bits/block
static uint8_t dead_block[LLC_SETS][LLC_WAYS]; // 2 bits/block

// Streaming detector
static uint64_t last_addr[LLC_SETS];
static int64_t last_delta[LLC_SETS];
static uint8_t stream_score[LLC_SETS]; // 8 bits/set

// DRRIP set-dueling: 64 leader sets
static const uint32_t NUM_LEADER_SETS = 64;
static uint32_t leader_sets_sr[NUM_LEADER_SETS];
static uint32_t leader_sets_br[NUM_LEADER_SETS];
// 10-bit PSEL
static uint16_t PSEL = 512; // 0..1023, mid=SRRIP, hi=BRRIP

// Helper: assign leader sets at init
void AssignLeaderSets() {
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i) {
        leader_sets_sr[i] = i * 2;
        leader_sets_br[i] = i * 2 + 1;
    }
}

// Streaming detector: true if streaming detected
inline bool IsStreaming(uint32_t set, uint64_t paddr) {
    int64_t delta = paddr - last_addr[set];
    if (delta == last_delta[set] && delta != 0) {
        if (stream_score[set] < 255) ++stream_score[set];
    } else {
        if (stream_score[set] > 0) --stream_score[set];
    }
    last_delta[set] = delta;
    last_addr[set] = paddr;
    return stream_score[set] >= 32;
}

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv));
    memset(dead_block, 0, sizeof(dead_block));
    memset(last_addr, 0, sizeof(last_addr));
    memset(last_delta, 0, sizeof(last_delta));
    memset(stream_score, 0, sizeof(stream_score));
    PSEL = 512;
    AssignLeaderSets();
}

// --- Find victim: prefer dead blocks, else RRIP ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Dead block first
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (dead_block[set][way] == 3)
            return way;
    // Standard RRIP victim
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] < 3) ++rrpv[set][way];
    }
    return 0;
}

// --- Update replacement state ---
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
    // Streaming detector per set
    bool streaming = IsStreaming(set, paddr);

    // Dead-block counters: decay every 4096 accesses
    static uint64_t access_count = 0;
    if ((++access_count & 0xFFF) == 0) {
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            for (uint32_t w = 0; w < LLC_WAYS; ++w)
                dead_block[s][w] >>= 1;
    }

    // DRRIP: leader sets for set-dueling
    bool is_sr_leader = false, is_br_leader = false;
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i) {
        if (set == leader_sets_sr[i]) is_sr_leader = true;
        if (set == leader_sets_br[i]) is_br_leader = true;
    }

    // On hit: promote to MRU, reset dead-block
    if (hit) {
        rrpv[set][way] = 0;
        dead_block[set][way] = 0;
        // Update PSEL if leader sets
        if (is_sr_leader && PSEL < 1023) ++PSEL;
        if (is_br_leader && PSEL > 0) --PSEL;
        return;
    }

    // On miss: increment dead-block counter for victim
    if (dead_block[set][way] < 3) ++dead_block[set][way];

    // --- Insertion policy ---
    // Streaming detected: bypass (do not insert) or insert at RRPV=3
    if (streaming) {
        rrpv[set][way] = 3;
        dead_block[set][way] = 0;
        return;
    }

    // DRRIP insertion depth
    uint8_t ins_rrpv = 2; // SRRIP default
    if (is_sr_leader)
        ins_rrpv = 2; // SRRIP leader: always RRPV=2
    else if (is_br_leader)
        ins_rrpv = (rand() % 32 == 0) ? 2 : 3; // BRRIP leader: RRPV=2 1/32, else 3
    else
        ins_rrpv = (PSEL >= 512) ? 2 : ((rand() % 32 == 0) ? 2 : 3); // follower sets

    rrpv[set][way] = ins_rrpv;
    dead_block[set][way] = 0;
}

// --- Print statistics ---
void PrintStats() {
    uint32_t streaming_sets = 0;
    for (uint32_t i = 0; i < LLC_SETS; ++i)
        if (stream_score[i] >= 32) ++streaming_sets;
    std::cout << "DRRIP-Stream-TDB Policy\n";
    std::cout << "Streaming sets: " << streaming_sets << " / " << LLC_SETS << "\n";
    std::cout << "PSEL: " << PSEL << " (SRRIP if >=512, BRRIP if <512)\n";
}

// --- Heartbeat stats ---
void PrintStats_Heartbeat() {
    uint32_t streaming_sets = 0;
    for (uint32_t i = 0; i < LLC_SETS; ++i)
        if (stream_score[i] >= 32) ++streaming_sets;
    std::cout << "[Heartbeat] Streaming sets: " << streaming_sets << " / " << LLC_SETS << "\n";
}