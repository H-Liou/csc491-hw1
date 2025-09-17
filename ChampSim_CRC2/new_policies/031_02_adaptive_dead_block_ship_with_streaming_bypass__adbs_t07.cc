#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// ---- RRIP metadata ----
uint8_t rrpv[LLC_SETS][LLC_WAYS]; // 2 bits per block

// ---- Dead-block predictor (per-line) ----
uint8_t dead_block[LLC_SETS][LLC_WAYS]; // 2 bits per block

// ---- SHiP-lite signature table ----
#define SHIP_SIG_BITS 6
#define SHIP_TABLE_SIZE 1024
struct SHIPEntry {
    uint8_t reuse_counter; // 2 bits
};
SHIPEntry ship_table[SHIP_TABLE_SIZE];

// ---- Per-line PC signatures ----
uint16_t line_sig[LLC_SETS][LLC_WAYS]; // 6 bits per line

// ---- Streaming detector ----
uint64_t last_addr[LLC_SETS]; // 48 bits per set (paddr)
uint8_t stream_score[LLC_SETS]; // 2 bits per set

// ---- DRRIP set-dueling ----
#define PSEL_BITS 10
uint16_t PSEL = (1 << (PSEL_BITS - 1)); // 10-bit selector

#define NUM_LEADER_SETS 64
uint8_t leader_set_type[NUM_LEADER_SETS]; // 0: SRRIP, 1: BRRIP

// ---- Other bookkeeping ----
uint64_t access_counter = 0;
#define DECAY_PERIOD 100000

// Helper: map set to leader set index (first NUM_LEADER_SETS sets are leaders)
inline int get_leader_set_idx(uint32_t set) {
    if (set < NUM_LEADER_SETS) return set;
    return -1;
}

// --- Initialize replacement state ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv)); // start as LRU
    memset(dead_block, 0, sizeof(dead_block)); // optimistic reuse
    memset(ship_table, 1, sizeof(ship_table)); // moderate reuse for PC signatures
    memset(line_sig, 0, sizeof(line_sig));
    memset(last_addr, 0, sizeof(last_addr));
    memset(stream_score, 0, sizeof(stream_score));
    memset(leader_set_type, 0, sizeof(leader_set_type));
    for (int i = 0; i < NUM_LEADER_SETS / 2; ++i)
        leader_set_type[i] = 0; // SRRIP
    for (int i = NUM_LEADER_SETS / 2; i < NUM_LEADER_SETS; ++i)
        leader_set_type[i] = 1; // BRRIP
    PSEL = (1 << (PSEL_BITS - 1));
    access_counter = 0;
}

// --- Victim selection: prioritize dead blocks ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // First prefer invalid block
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (!current_set[way].valid)
            return way;

    // Next, prefer blocks predicted dead (dead_block == 3)
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (dead_block[set][way] == 3)
            return way;

    // If none predicted dead, standard RRIP victim (max RRPV)
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            rrpv[set][way]++;
    }
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
    access_counter++;

    // ---- Streaming detector ----
    uint64_t last = last_addr[set];
    uint8_t score = stream_score[set];
    if (last == 0) {
        last_addr[set] = paddr;
        stream_score[set] = 0;
    } else {
        uint64_t delta = (paddr > last) ? (paddr - last) : (last - paddr);
        if (delta == 64 || delta == 128) { // 1–2 block stride
            if (score < 3) stream_score[set]++;
        } else {
            if (score > 0) stream_score[set]--;
        }
        last_addr[set] = paddr;
    }
    bool streaming = (stream_score[set] >= 2);

    // ---- SHiP signature extraction ----
    uint16_t sig = (uint16_t)((PC >> 2) & 0x3F); // 6 bits
    uint16_t ship_idx = sig;
    line_sig[set][way] = sig;

    // --- Dead-block predictor update ---
    if (hit) {
        dead_block[set][way] = 0; // re-reference, not dead
        if (ship_table[ship_idx].reuse_counter < 3)
            ship_table[ship_idx].reuse_counter++;
    } else {
        // If line evicted, increment dead-block (max 3)
        if (dead_block[set][way] < 3)
            dead_block[set][way]++;
        // Penalize previous SHiP signature
        uint16_t evict_sig = line_sig[set][way];
        if (ship_table[evict_sig].reuse_counter > 0)
            ship_table[evict_sig].reuse_counter--;
    }

    // ---- DRRIP set-dueling: leader sets update PSEL ----
    int leader_idx = get_leader_set_idx(set);
    if (leader_idx >= 0) {
        if (leader_set_type[leader_idx] == 0) { // SRRIP leader
            if (hit && PSEL < ((1 << PSEL_BITS) - 1)) PSEL++;
        } else { // BRRIP leader
            if (!hit && PSEL > 0) PSEL--;
        }
    }

    // --- Insertion policy ---
    // Streaming detected: bypass (do not insert, set RRPV=3)
    if (streaming) {
        rrpv[set][way] = 3;
        dead_block[set][way] = 3; // mark as dead
    } else {
        // Non-leader sets: choose insertion policy based on PSEL
        bool use_brrip = (PSEL < (1 << (PSEL_BITS - 1)));
        uint8_t insertion_rrpv = 2; // SRRIP default
        if (use_brrip) {
            // BRRIP: insert at RRPV=2 most, RRPV=3 rarely (1/32)
            if ((access_counter & 0x1F) == 0)
                insertion_rrpv = 3;
            else
                insertion_rrpv = 2;
        }
        // DIP-style: leader sets override insertion policy
        if (leader_idx >= 0) {
            if (leader_set_type[leader_idx] == 0)
                insertion_rrpv = 2;
            else
                insertion_rrpv = ((access_counter & 0x1F) == 0) ? 3 : 2;
        }
        // SHiP bias: high-reuse signature inserts at MRU (0)
        if (ship_table[ship_idx].reuse_counter >= 2)
            insertion_rrpv = 0;
        // Dead-block bias: if recently dead, insert at LRU (3)
        if (dead_block[set][way] >= 2)
            insertion_rrpv = 3;
        rrpv[set][way] = insertion_rrpv;
        // Dead-block reset if inserted at MRU
        if (insertion_rrpv == 0)
            dead_block[set][way] = 0;
    }
    line_sig[set][way] = sig;

    // ---- Periodic decay of SHiP counters and dead-block counters ----
    if (access_counter % DECAY_PERIOD == 0) {
        for (uint32_t i = 0; i < SHIP_TABLE_SIZE; ++i)
            if (ship_table[i].reuse_counter > 0)
                ship_table[i].reuse_counter--;
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            for (uint32_t w = 0; w < LLC_WAYS; ++w)
                if (dead_block[s][w] > 0) dead_block[s][w]--;
    }
}

// --- Statistics ---
void PrintStats() {
    int high_reuse_pcs = 0;
    for (int i = 0; i < SHIP_TABLE_SIZE; ++i)
        if (ship_table[i].reuse_counter >= 2) high_reuse_pcs++;
    int streaming_sets = 0;
    for (int i = 0; i < LLC_SETS; ++i)
        if (stream_score[i] >= 2) streaming_sets++;
    int dead_lines = 0;
    for (int i = 0; i < LLC_SETS; ++i)
        for (int j = 0; j < LLC_WAYS; ++j)
            if (dead_block[i][j] >= 2) dead_lines++;
    std::cout << "ADBS Policy: Adaptive Dead-Block SHiP with Streaming Bypass" << std::endl;
    std::cout << "High-reuse PC signatures: " << high_reuse_pcs << "/" << SHIP_TABLE_SIZE << std::endl;
    std::cout << "Streaming sets (score>=2): " << streaming_sets << "/" << LLC_SETS << std::endl;
    std::cout << "Dead lines (counter>=2): " << dead_lines << "/" << (LLC_SETS*LLC_WAYS) << std::endl;
    std::cout << "PSEL value: " << PSEL << std::endl;
}

void PrintStats_Heartbeat() {
    int high_reuse_pcs = 0;
    for (int i = 0; i < SHIP_TABLE_SIZE; ++i)
        if (ship_table[i].reuse_counter >= 2) high_reuse_pcs++;
    int streaming_sets = 0;
    for (int i = 0; i < LLC_SETS; ++i)
        if (stream_score[i] >= 2) streaming_sets++;
    int dead_lines = 0;
    for (int i = 0; i < LLC_SETS; ++i)
        for (int j = 0; j < LLC_WAYS; ++j)
            if (dead_block[i][j] >= 2) dead_lines++;
    std::cout << "High-reuse PC signatures (heartbeat): " << high_reuse_pcs << "/" << SHIP_TABLE_SIZE << std::endl;
    std::cout << "Streaming sets (heartbeat): " << streaming_sets << "/" << LLC_SETS << std::endl;
    std::cout << "Dead lines (heartbeat): " << dead_lines << "/" << (LLC_SETS*LLC_WAYS) << std::endl;
    std::cout << "PSEL value (heartbeat): " << PSEL << std::endl;
}