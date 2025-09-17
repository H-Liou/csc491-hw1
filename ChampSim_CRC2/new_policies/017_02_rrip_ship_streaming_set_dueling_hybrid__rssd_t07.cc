#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// DRRIP: 2-bit RRPV per block
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// DRRIP: 10-bit PSEL, 64 SRRIP leader sets, 64 BRRIP leader sets
#define PSEL_BITS 10
uint16_t PSEL = (1 << (PSEL_BITS-1)); // Start neutral
#define NUM_LEADER_SETS 64
std::vector<uint32_t> srrip_leader_sets, brrip_leader_sets;

// SHiP-lite: 6-bit PC signature table, 2-bit outcome counter per set
#define SHIP_SIG_BITS 6
#define SHIP_SIG_ENTRIES (1 << SHIP_SIG_BITS) // 64 entries
uint8_t ship_counter[LLC_SETS][SHIP_SIG_ENTRIES]; // 2 bits per entry
uint8_t block_sig[LLC_SETS][LLC_WAYS];           // 6 bits per block

// Streaming detector: per-set, last address and delta, 2-bit streaming counter
uint64_t last_addr[LLC_SETS];
int64_t last_delta[LLC_SETS];
uint8_t stream_ctr[LLC_SETS]; // 2 bits per set

// Helper: leader set assignment
void InitLeaderSets() {
    srrip_leader_sets.clear(); brrip_leader_sets.clear();
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i) {
        srrip_leader_sets.push_back(i);
        brrip_leader_sets.push_back(LLC_SETS - 1 - i);
    }
}

// Initialize replacement state
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv));
    memset(ship_counter, 1, sizeof(ship_counter));
    memset(block_sig, 0, sizeof(block_sig));
    memset(last_addr, 0, sizeof(last_addr));
    memset(last_delta, 0, sizeof(last_delta));
    memset(stream_ctr, 0, sizeof(stream_ctr));
    PSEL = (1 << (PSEL_BITS-1));
    InitLeaderSets();
}

// Streaming detector (called on every access/fill)
void UpdateStreamingDetector(uint32_t set, uint64_t paddr) {
    int64_t delta = (int64_t)paddr - (int64_t)last_addr[set];
    if (last_addr[set] != 0 && delta == last_delta[set]) {
        // Streaming stride detected
        if (stream_ctr[set] < 3) stream_ctr[set]++;
    } else {
        if (stream_ctr[set] > 0) stream_ctr[set]--;
    }
    last_delta[set] = delta;
    last_addr[set] = paddr;
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
    // Prefer invalid blocks
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (!current_set[way].valid)
            return way;
    // Standard RRIP victim search
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] < 3)
                rrpv[set][way]++;
    }
    return 0; // Should not reach
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
    // --- Streaming detection ---
    UpdateStreamingDetector(set, paddr);

    // --- SHiP signature ---
    uint8_t sig = (PC ^ (PC >> 8)) & (SHIP_SIG_ENTRIES - 1);

    // --- DRRIP set-dueling: determine insertion policy ---
    bool is_srrip_leader = std::find(srrip_leader_sets.begin(), srrip_leader_sets.end(), set) != srrip_leader_sets.end();
    bool is_brrip_leader = std::find(brrip_leader_sets.begin(), brrip_leader_sets.end(), set) != brrip_leader_sets.end();

    // On hit: promote to MRU, update SHiP outcome
    if (hit) {
        rrpv[set][way] = 0;
        // SHiP: increment outcome counter for signature
        if (ship_counter[set][block_sig[set][way]] < 3)
            ship_counter[set][block_sig[set][way]]++;
        return;
    }

    // --- On miss/fill: decide insertion depth ---
    uint8_t ins_rrpv = 2; // SRRIP default

    // SHiP: if reused signature, insert at MRU
    if (ship_counter[set][sig] >= 2)
        ins_rrpv = 0;

    // Streaming: if streaming detected, force distant RRPV (bypass)
    if (stream_ctr[set] >= 2)
        ins_rrpv = 3;

    // DRRIP set-dueling (leader sets influence PSEL)
    if (is_srrip_leader) {
        ins_rrpv = 2; // always SRRIP
    } else if (is_brrip_leader) {
        ins_rrpv = (rand() % 32 == 0) ? 2 : 3; // 1/32 SRRIP, else BRRIP
    } else {
        // Follower sets use PSEL to choose policy if not streaming/SHIPlite overrides
        if (stream_ctr[set] < 2 && ship_counter[set][sig] < 2) {
            if (PSEL >= (1 << (PSEL_BITS-1)))
                ins_rrpv = 2; // SRRIP
            else
                ins_rrpv = (rand() % 32 == 0) ? 2 : 3; // BRRIP
        }
        // If streaming or SHiP indicates, ins_rrpv already set above
    }

    rrpv[set][way] = ins_rrpv;
    block_sig[set][way] = sig;

    // DRRIP PSEL update: if miss in leader set, update PSEL
    if (!hit) {
        if (is_srrip_leader && ins_rrpv == 2 && PSEL < ((1 << PSEL_BITS) - 1))
            PSEL++;
        if (is_brrip_leader && (ins_rrpv == 3 || ins_rrpv == 2) && PSEL > 0)
            PSEL--;
    }

    // SHiP: if block inserted at distant RRPV, decrement outcome counter
    if (ship_counter[set][sig] > 0 && ins_rrpv == 3)
        ship_counter[set][sig]--;
}

// Print end-of-simulation statistics
void PrintStats() {
    // SHiP counter histogram
    uint64_t ship_hist[4] = {0};
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        for (uint32_t i = 0; i < SHIP_SIG_ENTRIES; ++i)
            ship_hist[ship_counter[s][i]]++;
    std::cout << "RSSD: SHiP outcome counter histogram: ";
    for (int i = 0; i < 4; ++i)
        std::cout << ship_hist[i] << " ";
    std::cout << std::endl;
    // Streaming histogram
    uint64_t stream_hist[4] = {0};
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        stream_hist[stream_ctr[s]]++;
    std::cout << "RSSD: Streaming counter histogram: ";
    for (int i = 0; i < 4; ++i)
        std::cout << stream_hist[i] << " ";
    std::cout << std::endl;
    // Print PSEL
    std::cout << "RSSD: Final PSEL value: " << PSEL << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Periodic decay: age streaming counters
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (stream_ctr[s] > 0)
            stream_ctr[s]--;
}