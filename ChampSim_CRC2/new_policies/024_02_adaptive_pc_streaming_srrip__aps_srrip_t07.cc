#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// ---- SRRIP Metadata: 2 bits per line ----
uint8_t rrpv[LLC_SETS][LLC_WAYS]; // 2 bits per block

// ---- Per-line PC signature: 6 bits per line ----
uint8_t line_sig[LLC_SETS][LLC_WAYS]; // 6 bits per line

// ---- SHiP-like PC table: 2 bits per 6-bit signature ----
#define PC_TABLE_SIZE 1024 // 6 bits
struct PCEntry { uint8_t reuse_counter; };
PCEntry pc_table[PC_TABLE_SIZE];

// ---- Streaming detector: per-set monotonicity ----
uint64_t last_addr[LLC_SETS]; // 48 bits per set
uint8_t stream_score[LLC_SETS]; // 2 bits per set

// ---- Periodic decay for streaming detector ----
uint64_t access_counter = 0;
#define STREAM_DECAY_PERIOD 100000

void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv));       // All blocks start as distant (3)
    memset(line_sig, 0, sizeof(line_sig));
    for (int i = 0; i < PC_TABLE_SIZE; ++i)
        pc_table[i].reuse_counter = 1;  // Start with neutral reuse
    memset(last_addr, 0, sizeof(last_addr));
    memset(stream_score, 0, sizeof(stream_score));
    access_counter = 0;
}

// Find victim in the set using SRRIP
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

    // SRRIP: select block with max RRPV (3), else increment all RRPV and retry
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] < 3)
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

    // ---- Streaming detector update ----
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

    // ---- PC signature extraction ----
    uint8_t sig = (uint8_t)((PC >> 2) & 0x3F); // 6 bits
    uint16_t pc_idx = sig;
    line_sig[set][way] = sig;

    // ---- PC table outcome update ----
    if (hit) {
        // On hit, promote block and increment PC reuse counter
        rrpv[set][way] = 0;
        if (pc_table[pc_idx].reuse_counter < 3)
            pc_table[pc_idx].reuse_counter++;
    } else {
        // On miss/evict, penalize previous signature
        uint8_t evict_sig = line_sig[set][way];
        if (pc_table[evict_sig].reuse_counter > 0)
            pc_table[evict_sig].reuse_counter--;
    }

    // ---- Insertion depth selection ----
    uint8_t insertion_rrpv = 3; // default: distant (SRRIP)
    // High-reuse PCs -> insert at MRU
    if (pc_table[pc_idx].reuse_counter >= 2)
        insertion_rrpv = 0;
    // Streaming + low-reuse PC: insert at distant (or bypass with probability)
    else if (streaming && pc_table[pc_idx].reuse_counter == 0) {
        // Bypass 80% of the time, else insert at distant
        if ((rand() % 100) < 80) {
            rrpv[set][way] = 3;
            line_sig[set][way] = sig;
            return; // block not promoted, acts as dead-on-arrival
        }
        insertion_rrpv = 3;
    }
    // Moderate reuse: insert at MRU-1
    else if (pc_table[pc_idx].reuse_counter == 1)
        insertion_rrpv = 1;

    rrpv[set][way] = insertion_rrpv;
    line_sig[set][way] = sig;

    // ---- Periodic decay of streaming detector ----
    if (access_counter % STREAM_DECAY_PERIOD == 0) {
        memset(stream_score, 0, sizeof(stream_score));
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    int high_reuse_pcs = 0;
    for (int i = 0; i < PC_TABLE_SIZE; ++i)
        if (pc_table[i].reuse_counter >= 2) high_reuse_pcs++;
    int streaming_sets = 0;
    for (int i = 0; i < LLC_SETS; ++i)
        if (stream_score[i] >= 2) streaming_sets++;
    std::cout << "APS-SRRIP Policy: Adaptive PC-Streaming SRRIP" << std::endl;
    std::cout << "High-reuse PC signatures: " << high_reuse_pcs << "/" << PC_TABLE_SIZE << std::endl;
    std::cout << "Streaming sets (score>=2): " << streaming_sets << "/" << LLC_SETS << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    int high_reuse_pcs = 0;
    for (int i = 0; i < PC_TABLE_SIZE; ++i)
        if (pc_table[i].reuse_counter >= 2) high_reuse_pcs++;
    int streaming_sets = 0;
    for (int i = 0; i < LLC_SETS; ++i)
        if (stream_score[i] >= 2) streaming_sets++;
    std::cout << "High-reuse PC signatures (heartbeat): " << high_reuse_pcs << "/" << PC_TABLE_SIZE << std::endl;
    std::cout << "Streaming sets (heartbeat): " << streaming_sets << "/" << LLC_SETS << std::endl;
}