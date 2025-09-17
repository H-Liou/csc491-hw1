#include <vector>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- SHiP-lite metadata ---
#define SIG_BITS 6
#define SIG_TABLE_SIZE 64
uint8_t block_sig[LLC_SETS][LLC_WAYS];      // Per-block signature
uint8_t ship_ctr[SIG_TABLE_SIZE];           // Per-signature 2-bit counter

// --- Dead-block counter metadata ---
uint8_t deadctr[LLC_SETS][LLC_WAYS];        // Per-block 2-bit dead-block counter

// --- RRIP metadata ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// --- Set-dueling for SRRIP vs SHiP-DBDI ---
#define DUEL_LEADER_SETS 32
#define PSEL_BITS 10
uint16_t psel = (1 << (PSEL_BITS-1));
uint8_t is_leader_srrip[LLC_SETS];
uint8_t is_leader_shipdbdi[LLC_SETS];

// Decay control for dead-block counter
uint64_t global_access_counter = 0;
#define DEADCTR_DECAY_PERIOD 2048

void InitReplacementState() {
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            rrpv[set][way] = 2;
            block_sig[set][way] = 0;
            deadctr[set][way] = 0;
        }
    for (int i = 0; i < SIG_TABLE_SIZE; ++i)
        ship_ctr[i] = 1;
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        is_leader_srrip[set] = 0;
        is_leader_shipdbdi[set] = 0;
    }
    for (uint32_t i = 0; i < DUEL_LEADER_SETS; ++i)
        is_leader_srrip[i] = 1;
    for (uint32_t i = DUEL_LEADER_SETS; i < 2*DUEL_LEADER_SETS; ++i)
        is_leader_shipdbdi[i] = 1;
    global_access_counter = 0;
}

// Victim selection: standard RRIP
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] < 3)
                ++rrpv[set][way];
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
    global_access_counter++;
    // Periodically decay dead-block counters to avoid staleness
    if ((global_access_counter & (DEADCTR_DECAY_PERIOD-1)) == 0) {
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            for (uint32_t w = 0; w < LLC_WAYS; ++w)
                if (deadctr[s][w] > 0) deadctr[s][w]--;
    }

    // --- Signature extraction ---
    uint8_t sig = ((PC >> 2) ^ (set & 0x3F)) & ((1 << SIG_BITS)-1);

    uint8_t old_sig = block_sig[set][way];

    if (hit) {
        // On hit, reward signature and clear dead-block counter
        if (ship_ctr[old_sig] < 3)
            ship_ctr[old_sig]++;
        deadctr[set][way] = 0;
        rrpv[set][way] = 0; // MRU
    } else {
        // On eviction, penalize signature if not reused
        if (ship_ctr[old_sig] > 0)
            ship_ctr[old_sig]--;
        // New block: record its signature and increment dead-block counter
        block_sig[set][way] = sig;
        deadctr[set][way] = (deadctr[set][way] < 3) ? deadctr[set][way]+1 : 3;

        // --- Insertion policy selection ---
        bool use_shipdbdi;
        if (is_leader_srrip[set])
            use_shipdbdi = false;
        else if (is_leader_shipdbdi[set])
            use_shipdbdi = true;
        else
            use_shipdbdi = (psel < (1 << (PSEL_BITS-1)));

        // SHiP-DBDI: combine signature and dead-block counter
        if (use_shipdbdi) {
            // Dead block likely: insert at distant RRPV or bypass
            if (deadctr[set][way] >= 2 && ship_ctr[sig] <= 1) {
                rrpv[set][way] = 3; // LRU/bypass
                // Update PSEL if leader
                if (is_leader_shipdbdi[set] && !hit) if (psel < ((1<<PSEL_BITS)-1)) psel++;
            }
            // Signature hot, dead-block counter low: insert MRU
            else if (ship_ctr[sig] >= 2 && deadctr[set][way] <= 1) {
                rrpv[set][way] = 0;
                if (is_leader_srrip[set] && !hit) if (psel > 0) psel--;
            }
            // Otherwise: insert at mid RRPV
            else {
                rrpv[set][way] = 2;
            }
        }
        else {
            // Baseline SRRIP: hot signature MRU, else mid
            if (ship_ctr[sig] >= 2)
                rrpv[set][way] = 0;
            else
                rrpv[set][way] = 2;
            if (is_leader_srrip[set] && !hit && ship_ctr[sig] >= 2)
                if (psel > 0) psel--;
        }
    }
}

void PrintStats() {
    int hot = 0, cold = 0;
    for (int i = 0; i < SIG_TABLE_SIZE; ++i) {
        if (ship_ctr[i] >= 2) hot++;
        else cold++;
    }
    std::cout << "SHiP-DBDI: Hot PC signatures: " << hot << " / " << SIG_TABLE_SIZE << std::endl;
    std::cout << "SHiP-DBDI: Cold PC signatures: " << cold << std::endl;

    int likely_dead = 0, likely_live = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (deadctr[set][way] >= 2) likely_dead++;
            else likely_live++;
    std::cout << "SHiP-DBDI: Likely dead blocks: " << likely_dead << " / " << (LLC_SETS*LLC_WAYS) << std::endl;
    std::cout << "SHiP-DBDI: Likely live blocks: " << likely_live << std::endl;
}

void PrintStats_Heartbeat() {
    int hot = 0;
    for (int i = 0; i < SIG_TABLE_SIZE; ++i)
        if (ship_ctr[i] >= 2) hot++;
    std::cout << "SHiP-DBDI: Hot signature count: " << hot << std::endl;
    int likely_dead = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (deadctr[set][way] >= 2) likely_dead++;
    std::cout << "SHiP-DBDI: Likely dead blocks: " << likely_dead << std::endl;
}