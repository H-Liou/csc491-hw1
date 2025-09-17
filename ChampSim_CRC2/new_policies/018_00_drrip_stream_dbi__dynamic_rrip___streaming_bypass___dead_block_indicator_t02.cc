#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- DRRIP Metadata ---
static uint8_t rrpv[LLC_SETS][LLC_WAYS]; // 2 bits per block

// --- Dead-block indicator ---
static uint8_t dead_block[LLC_SETS][LLC_WAYS]; // 2 bits per block

// --- Streaming detector ---
static uint64_t last_addr[LLC_SETS];
static int64_t last_delta[LLC_SETS];
static uint8_t stream_score[LLC_SETS]; // 8 bits per set

// --- DRRIP Set-Dueling ---
#define PSEL_BITS 10
static uint16_t PSEL = 512; // 10-bit saturating counter
#define NUM_LEADER_SETS 64
static bool is_srrip_leader[LLC_SETS];
static bool is_brrip_leader[LLC_SETS];

// --- Helper: streaming detection ---
inline bool IsStreaming(uint32_t set, uint64_t paddr) {
    int64_t delta = paddr - last_addr[set];
    if (delta == last_delta[set] && delta != 0) {
        if (stream_score[set] < 255) stream_score[set]++;
    } else {
        if (stream_score[set] > 0) stream_score[set]--;
    }
    last_delta[set] = delta;
    last_addr[set] = paddr;
    // Streaming if score >= 32
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

    // Assign leader sets for set-dueling (first 32 SRRIP, next 32 BRRIP)
    memset(is_srrip_leader, 0, sizeof(is_srrip_leader));
    memset(is_brrip_leader, 0, sizeof(is_brrip_leader));
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i) {
        is_srrip_leader[i] = true;
        is_brrip_leader[i + NUM_LEADER_SETS] = true;
    }
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
    // First, try to evict block with dead_block==3
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (dead_block[set][way] == 3)
            return way;
    // Next, standard RRIP: find block with RRPV==3
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        // Aging: increment all RRPVs < 3
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
    // --- Streaming detector ---
    bool streaming = IsStreaming(set, paddr);

    // --- Dead-block counter decay: every 4096 accesses, halve all counters ---
    static uint64_t access_count = 0;
    if ((++access_count & 0xFFF) == 0) {
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            for (uint32_t w = 0; w < LLC_WAYS; ++w)
                dead_block[s][w] >>= 1;
    }

    // On hit: promote to MRU, reset dead-block counter
    if (hit) {
        rrpv[set][way] = 0;
        dead_block[set][way] = 0;
        return;
    }

    // On miss: increment dead-block counter for victim
    if (dead_block[set][way] < 3)
        ++dead_block[set][way];

    // --- DRRIP insertion depth selection ---
    bool srrip_insert = false;
    bool brrip_insert = false;
    if (is_srrip_leader[set])
        srrip_insert = true;
    else if (is_brrip_leader[set])
        brrip_insert = true;
    else
        srrip_insert = (PSEL >= 512);

    // --- Streaming logic ---
    if (streaming) {
        // Streaming detected: bypass (do not insert), or insert at RRPV=3
        rrpv[set][way] = 3;
    } else if (srrip_insert) {
        // SRRIP: insert at RRPV=2
        rrpv[set][way] = 2;
    } else if (brrip_insert) {
        // BRRIP: insert at RRPV=3 with low probability (1/32), else RRPV=2
        static uint32_t brripep = 0;
        if ((++brripep & 0x1F) == 0)
            rrpv[set][way] = 3;
        else
            rrpv[set][way] = 2;
    }

    // --- Set-dueling feedback ---
    if (is_srrip_leader[set] && hit)
        if (PSEL < 1023) ++PSEL;
    if (is_brrip_leader[set] && hit)
        if (PSEL > 0) --PSEL;

    // Reset dead-block counter on insertion
    dead_block[set][way] = 0;
}

// --- Print statistics ---
void PrintStats() {
    uint32_t streaming_sets = 0;
    for (uint32_t i = 0; i < LLC_SETS; ++i)
        if (stream_score[i] >= 32) ++streaming_sets;
    std::cout << "DRRIP-Stream-DBI Policy\n";
    std::cout << "Streaming sets: " << streaming_sets << " / " << LLC_SETS << "\n";
    std::cout << "PSEL value: " << PSEL << " (SRRIP if >=512, BRRIP if <512)\n";
}

// --- Heartbeat stats ---
void PrintStats_Heartbeat() {
    uint32_t streaming_sets = 0;
    for (uint32_t i = 0; i < LLC_SETS; ++i)
        if (stream_score[i] >= 32) ++streaming_sets;
    std::cout << "[Heartbeat] Streaming sets: " << streaming_sets << " / " << LLC_SETS << "\n";
}