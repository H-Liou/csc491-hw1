#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- DRRIP metadata ---
static uint8_t rrpv[LLC_SETS][LLC_WAYS];      // 2 bits per line
static uint8_t deadctr[LLC_SETS][LLC_WAYS];   // 2 bits per line (dead-block counter)

// --- DRRIP set-dueling ---
static const uint32_t NUM_LEADER_SETS = 32;   // 16 for SRRIP, 16 for BRRIP
static uint32_t srrip_leader_sets[NUM_LEADER_SETS];
static uint32_t brrip_leader_sets[NUM_LEADER_SETS];
static uint16_t psel = 512;                   // 10 bits, midpoint=512

// --- Streaming detector ---
static uint64_t last_addr[LLC_SETS];
static int64_t last_delta[LLC_SETS];
static uint8_t stream_ctr[LLC_SETS];          // 2 bits per set

// --- Dead-block decay epoch ---
static uint64_t access_epoch = 0;
static const uint64_t DECAY_PERIOD = 100000;  // Decay every N accesses

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv));      // All lines: RRPV=3 (long re-use distance)
    memset(deadctr, 0, sizeof(deadctr));
    memset(last_addr, 0, sizeof(last_addr));
    memset(last_delta, 0, sizeof(last_delta));
    memset(stream_ctr, 0, sizeof(stream_ctr));
    psel = 512;

    // Choose leader sets (fixed hash for reproducibility)
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i) {
        srrip_leader_sets[i] = (i * 13) % LLC_SETS;
        brrip_leader_sets[i] = ((i * 13) + 7) % LLC_SETS;
    }
}

// --- Streaming detector update ---
inline bool IsStreaming(uint32_t set, uint64_t paddr) {
    int64_t delta = paddr - last_addr[set];
    bool streaming = false;
    if (last_delta[set] != 0 && delta == last_delta[set]) {
        if (stream_ctr[set] < 3) ++stream_ctr[set];
    } else {
        if (stream_ctr[set] > 0) --stream_ctr[set];
    }
    streaming = (stream_ctr[set] >= 2);
    last_delta[set] = delta;
    last_addr[set] = paddr;
    return streaming;
}

// --- DRRIP insertion policy selection ---
inline bool UseSRRIP(uint32_t set) {
    // Leader sets: fixed policy; others: follow psel
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i) {
        if (set == srrip_leader_sets[i]) return true;
        if (set == brrip_leader_sets[i]) return false;
    }
    return (psel >= 512);
}

// --- Find victim (SRRIP) ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Standard SRRIP victim selection
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
    access_epoch++;
    // --- Streaming detection ---
    bool streaming = IsStreaming(set, paddr);

    // --- Dead-block decay ---
    if (access_epoch % DECAY_PERIOD == 0) {
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            for (uint32_t w = 0; w < LLC_WAYS; ++w)
                if (deadctr[s][w] > 0) deadctr[s][w]--;
    }

    // --- On hit: promote to MRU, mark as not dead ---
    if (hit) {
        rrpv[set][way] = 0;
        if (deadctr[set][way] > 0) deadctr[set][way]--;
        return;
    }

    // --- On eviction: update dead-block counter ---
    if (deadctr[set][way] < 3) deadctr[set][way]++;
    // (No per-set dead-block table, just per-line approximation)

    // --- DRRIP set-dueling update ---
    // Only update PSEL for leader sets
    bool is_srrip_leader = false, is_brrip_leader = false;
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i) {
        if (set == srrip_leader_sets[i]) is_srrip_leader = true;
        if (set == brrip_leader_sets[i]) is_brrip_leader = true;
    }
    if (is_srrip_leader && hit) {
        if (psel < 1023) psel++;
    }
    if (is_brrip_leader && hit) {
        if (psel > 0) psel--;
    }

    // --- Streaming-aware bypass & dead-block insertion bias ---
    if (streaming || deadctr[set][way] == 3) {
        // Insert at distant RRPV (bypass effect)
        rrpv[set][way] = 3;
        deadctr[set][way] = 0; // Reset for new block
        return;
    }

    // --- DRRIP insertion depth ---
    bool use_srrip = UseSRRIP(set);
    if (use_srrip) {
        rrpv[set][way] = 2; // SRRIP: insert at RRPV=2
    } else {
        // BRRIP: insert at RRPV=2 with low probability, else RRPV=3
        if ((rand() & 0x1F) == 0) // ~1/32 probability
            rrpv[set][way] = 2;
        else
            rrpv[set][way] = 3;
    }
    deadctr[set][way] = 0; // Reset for new block
}

// --- Print statistics ---
void PrintStats() {
    std::cout << "DRRIP-SDBP Policy: DRRIP + Streaming-Aware Dead-Block Predictor\n";
    std::cout << "PSEL value: " << psel << std::endl;
    // Streaming counter histogram
    uint32_t stream_hist[4] = {0,0,0,0};
    for (uint32_t i = 0; i < LLC_SETS; ++i)
        stream_hist[stream_ctr[i]]++;
    std::cout << "Streaming counter histogram: ";
    for (int i=0; i<4; ++i) std::cout << stream_hist[i] << " ";
    std::cout << std::endl;
    // Dead-block counter histogram
    uint32_t dead_hist[4] = {0,0,0,0};
    for (uint32_t s=0; s<LLC_SETS; ++s)
        for (uint32_t w=0; w<LLC_WAYS; ++w)
            dead_hist[deadctr[s][w]]++;
    std::cout << "Dead-block counter histogram: ";
    for (int i=0; i<4; ++i) std::cout << dead_hist[i] << " ";
    std::cout << std::endl;
}

void PrintStats_Heartbeat() {}