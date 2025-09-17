#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// ---- RRIP Metadata ----
uint8_t rrpv[LLC_SETS][LLC_WAYS]; // 2 bits per block

// ---- SHiP-lite: Signature table ----
#define SHIP_TABLE_SIZE 1024 // 6-bit index (PC % 1024)
struct SHIPEntry {
    uint8_t reuse_counter; // 2 bits
};
SHIPEntry ship_table[SHIP_TABLE_SIZE];

// ---- Per-line PC signatures ----
uint16_t line_sig[LLC_SETS][LLC_WAYS]; // 6 bits per line

// ---- Per-line tiny reuse counter (2 bits) ----
uint8_t line_reuse[LLC_SETS][LLC_WAYS]; // 2 bits per line

// ---- Streaming detector: per-set monotonicity ----
uint64_t last_addr[LLC_SETS]; // 48 bits per set (paddr)
uint8_t stream_score[LLC_SETS]; // 2 bits per set

// ---- DRRIP set-dueling for SRRIP/BRRIP ----
#define NUM_LEADER_SETS 32
uint8_t is_srrip_leader[LLC_SETS];
uint8_t is_brrip_leader[LLC_SETS];
uint16_t psel; // 10 bits

// ---- Periodic decay for per-line reuse ----
uint64_t access_counter = 0;
#define DECAY_PERIOD 100000

void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv));
    memset(ship_table, 1, sizeof(ship_table));
    memset(line_sig, 0, sizeof(line_sig));
    memset(line_reuse, 0, sizeof(line_reuse));
    memset(is_srrip_leader, 0, sizeof(is_srrip_leader));
    memset(is_brrip_leader, 0, sizeof(is_brrip_leader));
    memset(last_addr, 0, sizeof(last_addr));
    memset(stream_score, 0, sizeof(stream_score));
    psel = (1 << 9); // 512

    // Assign leader sets: first NUM_LEADER_SETS for SRRIP, next NUM_LEADER_SETS for BRRIP
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i) {
        is_srrip_leader[i] = 1;
        is_brrip_leader[LLC_SETS/2 + i] = 1;
    }
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
    // Prefer invalid block
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (!current_set[way].valid)
            return way;

    // RRIP: select block with max RRPV (3), else increment all RRPV
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            rrpv[set][way]++;
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
    uint16_t ship_idx = sig; // Use as index
    line_sig[set][way] = sig;

    // ---- SHiP outcome update ----
    if (hit) {
        // On hit, promote block and increment reuse counter
        rrpv[set][way] = 0;
        if (ship_table[ship_idx].reuse_counter < 3)
            ship_table[ship_idx].reuse_counter++;
        if (line_reuse[set][way] < 3)
            line_reuse[set][way]++;
    } else {
        // On miss/evict, penalize previous signature if block had low reuse
        uint16_t evict_sig = line_sig[set][way];
        if (line_reuse[set][way] == 0 && ship_table[evict_sig].reuse_counter > 0)
            ship_table[evict_sig].reuse_counter--;
        line_reuse[set][way] = 0;
    }

    // ---- DRRIP set-dueling: choose insertion policy ----
    bool use_brrip = false;
    if (is_srrip_leader[set]) {
        use_brrip = false;
    } else if (is_brrip_leader[set]) {
        use_brrip = true;
    } else {
        use_brrip = (psel >= (1 << 9));
    }

    // ---- Insertion depth selection ----
    uint8_t insertion_rrpv = 2; // default: SRRIP (insert at RRPV=2)
    if (use_brrip) {
        insertion_rrpv = (rand() % 100 < 5) ? 2 : 3; // BRRIP: 5% insert at RRPV=2, 95% at RRPV=3
    }

    // ---- SHiP bias: high-reuse PCs insert at MRU ----
    if (ship_table[ship_idx].reuse_counter >= 2)
        insertion_rrpv = 0;

    // ---- Streaming logic: streaming sets bypass low-reuse PCs ----
    if (streaming && ship_table[ship_idx].reuse_counter == 0) {
        // Bypass: do not insert block, leave metadata as is
        rrpv[set][way] = 3;
        line_reuse[set][way] = 0;
        line_sig[set][way] = sig;
        return;
    }

    rrpv[set][way] = insertion_rrpv;
    line_reuse[set][way] = 0;
    line_sig[set][way] = sig;

    // ---- Set-dueling PSEL update ----
    if (is_srrip_leader[set]) {
        if (hit && psel < 1023) psel++;
    } else if (is_brrip_leader[set]) {
        if (hit && psel > 0) psel--;
    }

    // ---- Periodic decay of per-line reuse counters ----
    if (access_counter % DECAY_PERIOD == 0) {
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            for (uint32_t w = 0; w < LLC_WAYS; ++w)
                line_reuse[s][w] = 0;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    int high_reuse_pcs = 0;
    for (int i = 0; i < SHIP_TABLE_SIZE; ++i)
        if (ship_table[i].reuse_counter >= 2) high_reuse_pcs++;
    int streaming_sets = 0;
    for (int i = 0; i < LLC_SETS; ++i)
        if (stream_score[i] >= 2) streaming_sets++;
    int high_reuse_lines = 0;
    for (int i = 0; i < LLC_SETS; ++i)
        for (int j = 0; j < LLC_WAYS; ++j)
            if (line_reuse[i][j] >= 2) high_reuse_lines++;
    std::cout << "SG-DRRIP-SB Policy: Signature-Guided Dynamic RRIP + Streaming Bypass" << std::endl;
    std::cout << "High-reuse PC signatures: " << high_reuse_pcs << "/" << SHIP_TABLE_SIZE << std::endl;
    std::cout << "Streaming sets (score>=2): " << streaming_sets << "/" << LLC_SETS << std::endl;
    std::cout << "High-reuse lines: " << high_reuse_lines << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "Final PSEL value: " << psel << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    int high_reuse_pcs = 0;
    for (int i = 0; i < SHIP_TABLE_SIZE; ++i)
        if (ship_table[i].reuse_counter >= 2) high_reuse_pcs++;
    int streaming_sets = 0;
    for (int i = 0; i < LLC_SETS; ++i)
        if (stream_score[i] >= 2) streaming_sets++;
    int high_reuse_lines = 0;
    for (int i = 0; i < LLC_SETS; ++i)
        for (int j = 0; j < LLC_WAYS; ++j)
            if (line_reuse[i][j] >= 2) high_reuse_lines++;
    std::cout << "High-reuse PC signatures (heartbeat): " << high_reuse_pcs << "/" << SHIP_TABLE_SIZE << std::endl;
    std::cout << "Streaming sets (heartbeat): " << streaming_sets << "/" << LLC_SETS << std::endl;
    std::cout << "High-reuse lines (heartbeat): " << high_reuse_lines << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
}