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

// ---- DIP set-dueling for insertion preference ----
#define NUM_LEADER_SETS 64
uint8_t leader_LIP[LLC_SETS]; // 1 if LIP leader, 0 otherwise
uint8_t leader_BIP[LLC_SETS]; // 1 if BIP leader, 0 otherwise
uint16_t psel = 512; // 10-bit PSEL, midpoint

// ---- Streaming detector: per-set monotonicity ----
uint64_t last_addr[LLC_SETS]; // 48 bits per set
uint8_t stream_score[LLC_SETS]; // 2 bits per set

// ---- SHiP-lite signature table ----
#define SHIP_SIG_BITS 6
#define SHIP_TABLE_SIZE 1024
struct SHIPEntry {
    uint8_t reuse_counter; // 2 bits
};
SHIPEntry ship_table[SHIP_TABLE_SIZE];

// ---- Per-line PC signatures ----
uint16_t line_sig[LLC_SETS][LLC_WAYS]; // 6 bits per line

// ---- Other bookkeeping ----
uint64_t access_counter = 0;
#define DECAY_PERIOD 100000

void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv));
    memset(leader_LIP, 0, sizeof(leader_LIP));
    memset(leader_BIP, 0, sizeof(leader_BIP));
    memset(ship_table, 1, sizeof(ship_table));
    memset(line_sig, 0, sizeof(line_sig));
    memset(last_addr, 0, sizeof(last_addr));
    memset(stream_score, 0, sizeof(stream_score));
    access_counter = 0;
    psel = 512;

    // Assign leader sets: first 32 for LIP, next 32 for BIP
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i) {
        leader_LIP[i] = 1;
        leader_BIP[i] = 0;
    }
    for (uint32_t i = NUM_LEADER_SETS; i < 2 * NUM_LEADER_SETS; ++i) {
        leader_LIP[i] = 0;
        leader_BIP[i] = 1;
    }
}

uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Prefer invalid block
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (!current_set[way].valid)
            return way;

    // SRRIP: select block with max RRPV (3)
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            rrpv[set][way]++;
    }
}

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
        if (delta == 64 || delta == 128) { // 1-2 block stride
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

    // ---- SHiP outcome update ----
    if (hit) {
        rrpv[set][way] = 0; // promote on hit
        if (ship_table[ship_idx].reuse_counter < 3)
            ship_table[ship_idx].reuse_counter++;
    } else {
        // Penalize previous signature
        uint16_t evict_sig = line_sig[set][way];
        if (ship_table[evict_sig].reuse_counter > 0)
            ship_table[evict_sig].reuse_counter--;
    }

    // ---- DIP set-dueling: leader sets update ----
    bool is_LIP_leader = leader_LIP[set];
    bool is_BIP_leader = leader_BIP[set];

    // On miss in leader sets, update PSEL
    if (!hit) {
        if (is_LIP_leader && psel < 1023) psel++;
        if (is_BIP_leader && psel > 0)    psel--;
    }

    // ---- Insertion policy ----
    uint8_t insertion_rrpv = 3; // default: LRU (bypass)
    if (streaming) {
        insertion_rrpv = 3; // streaming: bypass
    } else {
        // DIP: choose insertion depth
        bool use_LIP = false, use_BIP = false;
        if (is_LIP_leader) use_LIP = true;
        else if (is_BIP_leader) use_BIP = true;
        else use_LIP = (psel >= 512);

        if (use_LIP) insertion_rrpv = 3; // LIP: insert at LRU
        else if (use_BIP) insertion_rrpv = (access_counter % 32 == 0) ? 0 : 3; // BIP: MRU every 32nd insert
        else insertion_rrpv = 3; // fallback

        // SHiP bias: high-reuse signature inserts at MRU
        if (ship_table[ship_idx].reuse_counter >= 2)
            insertion_rrpv = 0;
    }
    rrpv[set][way] = insertion_rrpv;
    line_sig[set][way] = sig;

    // ---- Periodic decay of SHiP counters ----
    if (access_counter % DECAY_PERIOD == 0) {
        for (uint32_t i = 0; i < SHIP_TABLE_SIZE; ++i)
            if (ship_table[i].reuse_counter > 0)
                ship_table[i].reuse_counter--;
    }
}

void PrintStats() {
    int high_reuse_pcs = 0;
    for (int i = 0; i < SHIP_TABLE_SIZE; ++i)
        if (ship_table[i].reuse_counter >= 2) high_reuse_pcs++;
    int streaming_sets = 0;
    for (int i = 0; i < LLC_SETS; ++i)
        if (stream_score[i] >= 2) streaming_sets++;
    std::cout << "DIPSS Policy: Dynamic Insertion Preference with Streaming and Signature" << std::endl;
    std::cout << "High-reuse PC signatures: " << high_reuse_pcs << "/" << SHIP_TABLE_SIZE << std::endl;
    std::cout << "Streaming sets (score>=2): " << streaming_sets << "/" << LLC_SETS << std::endl;
    std::cout << "PSEL value: " << psel << std::endl;
}

void PrintStats_Heartbeat() {
    int high_reuse_pcs = 0;
    for (int i = 0; i < SHIP_TABLE_SIZE; ++i)
        if (ship_table[i].reuse_counter >= 2) high_reuse_pcs++;
    int streaming_sets = 0;
    for (int i = 0; i < LLC_SETS; ++i)
        if (stream_score[i] >= 2) streaming_sets++;
    std::cout << "High-reuse PC signatures (heartbeat): " << high_reuse_pcs << "/" << SHIP_TABLE_SIZE << std::endl;
    std::cout << "Streaming sets (heartbeat): " << streaming_sets << "/" << LLC_SETS << std::endl;
    std::cout << "PSEL value (heartbeat): " << psel << std::endl;
}