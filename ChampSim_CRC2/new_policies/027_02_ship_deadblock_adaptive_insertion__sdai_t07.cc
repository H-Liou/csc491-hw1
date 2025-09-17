#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// ---- RRIP Metadata (SRRIP/BRRIP per block) ----
uint8_t rrpv[LLC_SETS][LLC_WAYS]; // 2 bits per block

// ---- SHiP-lite: Signature table ----
#define SHIP_SIG_BITS 6
#define SHIP_TABLE_SIZE 1024 // 6 bits, 1024 entries
struct SHIPEntry {
    uint8_t reuse_counter; // 2 bits
};
SHIPEntry ship_table[SHIP_TABLE_SIZE];

// ---- Per-line PC signatures ----
uint16_t line_sig[LLC_SETS][LLC_WAYS]; // 6 bits per line

// ---- DRRIP Set-dueling ----
#define LEADER_SETS 64
uint8_t leader_flags[LLC_SETS]; // 0: normal, 1: SRRIP leader, 2: BRRIP leader
uint16_t psel; // 10 bits (0..1023)

// ---- Dead-block detector (per-line) ----
uint8_t dead_block[LLC_SETS][LLC_WAYS]; // 1 bit per block

// ---- Streaming detector: per-set ----
uint8_t streaming_flag[LLC_SETS]; // 1 bit per set

// ---- Other bookkeeping ----
uint64_t last_addr[LLC_SETS]; // 48 bits per set (paddr)
uint64_t access_counter = 0;
#define DECAY_PERIOD 100000

void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv));
    memset(ship_table, 1, sizeof(ship_table));
    memset(line_sig, 0, sizeof(line_sig));
    memset(leader_flags, 0, sizeof(leader_flags));
    memset(dead_block, 0, sizeof(dead_block));
    memset(streaming_flag, 0, sizeof(streaming_flag));
    memset(last_addr, 0, sizeof(last_addr));
    access_counter = 0;

    // Assign leader sets: evenly spaced, first 32 SRRIP, next 32 BRRIP
    for (uint32_t i = 0; i < LEADER_SETS; ++i) {
        uint32_t srrip_set = (i * (LLC_SETS / (2 * LEADER_SETS)));
        uint32_t brrip_set = srrip_set + (LLC_SETS / 2);
        leader_flags[srrip_set] = 1; // SRRIP leader
        leader_flags[brrip_set] = 2; // BRRIP leader
    }
    psel = 512; // midpoint
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

    // RRIP: select block with max RRPV (3)
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
    if (last == 0) {
        last_addr[set] = paddr;
        streaming_flag[set] = 0;
    } else {
        uint64_t delta = (paddr > last) ? (paddr - last) : (last - paddr);
        // If stride is always 64 or 128, flag as streaming
        if (delta == 64 || delta == 128)
            streaming_flag[set] = 1;
        else
            streaming_flag[set] = 0;
        last_addr[set] = paddr;
    }
    bool streaming = (streaming_flag[set] == 1);

    // ---- SHiP signature extraction ----
    uint16_t sig = (uint16_t)((PC >> 2) & 0x3F); // 6 bits
    uint16_t ship_idx = sig;
    line_sig[set][way] = sig;

    // ---- Dead-block update ----
    if (hit) {
        dead_block[set][way] = 0; // reused
        rrpv[set][way] = 0; // promote on hit
        if (ship_table[ship_idx].reuse_counter < 3)
            ship_table[ship_idx].reuse_counter++;
    } else {
        // On miss/evict, penalize previous signature
        uint16_t evict_sig = line_sig[set][way];
        if (ship_table[evict_sig].reuse_counter > 0)
            ship_table[evict_sig].reuse_counter--;
        // If not reused before eviction, set dead-block bit
        if (dead_block[set][way] == 0)
            dead_block[set][way] = 1;
    }

    // ---- DRRIP insertion depth selection ----
    uint8_t leader = leader_flags[set];
    bool use_brrip = false;
    if (leader == 1)
        use_brrip = false; // SRRIP leader
    else if (leader == 2)
        use_brrip = true; // BRRIP leader
    else
        use_brrip = (psel >= 512); // follower sets

    // Default insertion depth
    uint8_t insertion_rrpv = 2; // SRRIP: insert at 2
    if (use_brrip)
        insertion_rrpv = ((rand() % 32) == 0) ? 2 : 3;

    // ---- Adaptive bias: SHiP and dead-block
    if (ship_table[ship_idx].reuse_counter >= 2 && dead_block[set][way] == 0)
        insertion_rrpv = 0; // strong reuse, insert at MRU
    else if (dead_block[set][way] == 1 || streaming)
        insertion_rrpv = 3; // dead-block or streaming: insert at LRU

    rrpv[set][way] = insertion_rrpv;
    line_sig[set][way] = sig;

    // ---- DRRIP set-dueling update ----
    if (!hit) {
        if (leader == 1 && !streaming) { // SRRIP leader
            if (psel < 1023) psel++;
        }
        else if (leader == 2 && !streaming) { // BRRIP leader
            if (psel > 0) psel--;
        }
    }

    // ---- Periodic decay of SHiP and dead-block bits ----
    if (access_counter % DECAY_PERIOD == 0) {
        for (uint32_t i = 0; i < SHIP_TABLE_SIZE; ++i)
            if (ship_table[i].reuse_counter > 0)
                ship_table[i].reuse_counter--;
        // Decay dead-block bits
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            for (uint32_t w = 0; w < LLC_WAYS; ++w)
                dead_block[s][w] = 0;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    int high_reuse_pcs = 0;
    for (int i = 0; i < SHIP_TABLE_SIZE; ++i)
        if (ship_table[i].reuse_counter >= 2) high_reuse_pcs++;
    int dead_blocks = 0;
    for (int s = 0; s < LLC_SETS; ++s)
        for (int w = 0; w < LLC_WAYS; ++w)
            if (dead_block[s][w] == 1) dead_blocks++;
    int streaming_sets = 0;
    for (int i = 0; i < LLC_SETS; ++i)
        if (streaming_flag[i] == 1) streaming_sets++;
    std::cout << "SDAI Policy: SHiP-DeadBlock Adaptive Insertion" << std::endl;
    std::cout << "High-reuse PC signatures: " << high_reuse_pcs << "/" << SHIP_TABLE_SIZE << std::endl;
    std::cout << "Dead blocks (end): " << dead_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "Streaming sets (flag=1): " << streaming_sets << "/" << LLC_SETS << std::endl;
    std::cout << "Final PSEL: " << psel << " (0=SRRIP, 1023=BRRIP)" << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    int high_reuse_pcs = 0;
    for (int i = 0; i < SHIP_TABLE_SIZE; ++i)
        if (ship_table[i].reuse_counter >= 2) high_reuse_pcs++;
    int dead_blocks = 0;
    for (int s = 0; s < LLC_SETS; ++s)
        for (int w = 0; w < LLC_WAYS; ++w)
            if (dead_block[s][w] == 1) dead_blocks++;
    int streaming_sets = 0;
    for (int i = 0; i < LLC_SETS; ++i)
        if (streaming_flag[i] == 1) streaming_sets++;
    std::cout << "High-reuse PC signatures (heartbeat): " << high_reuse_pcs << "/" << SHIP_TABLE_SIZE << std::endl;
    std::cout << "Dead blocks (heartbeat): " << dead_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "Streaming sets (heartbeat): " << streaming_sets << "/" << LLC_SETS << std::endl;
    std::cout << "PSEL (heartbeat): " << psel << " (0=SRRIP, 1023=BRRIP)" << std::endl;
}