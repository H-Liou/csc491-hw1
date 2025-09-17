#include <vector>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// ---- RRIP Metadata ----
uint8_t rrpv[LLC_SETS][LLC_WAYS]; // 2 bits per block

// ---- SHiP-lite: Signature table ----
#define SHIP_SIG_BITS 6
#define SHIP_TABLE_SIZE 1024
struct SHIPEntry {
    uint8_t reuse_counter; // 2 bits
};
SHIPEntry ship_table[SHIP_TABLE_SIZE];

// ---- Per-line PC signatures ----
uint16_t line_sig[LLC_SETS][LLC_WAYS]; // 6 bits per line

// ---- Dead-block: per-line dead counter ----
uint8_t dead_counter[LLC_SETS][LLC_WAYS]; // 2 bits per line

// ---- Streaming detector: per-set monotonicity ----
uint64_t last_addr[LLC_SETS]; // 48 bits per set (paddr)
uint8_t stream_score[LLC_SETS]; // 2 bits per set

// ---- Set-dueling for SRRIP/BRRIP ----
#define LEADER_SETS 64
uint8_t leader_flags[LLC_SETS]; // 0: normal, 1: SRRIP leader, 2: BRRIP leader
uint16_t psel; // 10 bits (0..1023)

// ---- Other bookkeeping ----
uint64_t access_counter = 0;
#define DECAY_PERIOD 100000

void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv));
    memset(ship_table, 1, sizeof(ship_table));
    memset(line_sig, 0, sizeof(line_sig));
    memset(dead_counter, 0, sizeof(dead_counter));
    memset(leader_flags, 0, sizeof(leader_flags));
    memset(last_addr, 0, sizeof(last_addr));
    memset(stream_score, 0, sizeof(stream_score));
    access_counter = 0;

    // Assign leader sets: first 32 SRRIP, next 32 BRRIP, evenly spaced
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

    // ---- Dead-block update ----
    if (hit) {
        // Block reused: reset dead counter
        dead_counter[set][way] = 0;
    } else {
        // Block was replaced; increment dead counter for previous occupant
        uint16_t evict_way = way;
        if (dead_counter[set][evict_way] < 3)
            dead_counter[set][evict_way]++;
    }

    // ---- SHiP outcome update ----
    if (hit) {
        // Promote block and increment SHiP counter
        rrpv[set][way] = 0;
        if (ship_table[ship_idx].reuse_counter < 3)
            ship_table[ship_idx].reuse_counter++;
    } else {
        // Penalize previous signature
        uint16_t evict_sig = line_sig[set][way];
        if (ship_table[evict_sig].reuse_counter > 0)
            ship_table[evict_sig].reuse_counter--;
    }

    // ---- Set-dueling insertion depth selection ----
    uint8_t leader = leader_flags[set];
    bool use_srrip = false;
    if (leader == 1)      use_srrip = true;   // SRRIP leader
    else if (leader == 2) use_srrip = false;  // BRRIP leader
    else                  use_srrip = (psel >= 512); // followers

    // Default insertion depth
    uint8_t insertion_rrpv = 2; // SRRIP: insert at 2, BRRIP: insert at 2 (6% at 3)
    if (!use_srrip) {
        insertion_rrpv = ((rand() % 16) == 0) ? 3 : 2; // BRRIP: mostly 2, sometimes 3
    }

    // ---- SHiP bias ----
    if (ship_table[ship_idx].reuse_counter >= 2)
        insertion_rrpv = 0; // high-reuse: MRU

    // ---- Dead-block bias ----
    if (dead_counter[set][way] >= 2)
        insertion_rrpv = 3; // dead block: LRU

    // ---- Streaming detector ----
    if (streaming && ship_table[ship_idx].reuse_counter < 2 && dead_counter[set][way] >= 2)
        insertion_rrpv = 3; // streaming + dead: LRU

    rrpv[set][way] = insertion_rrpv;
    line_sig[set][way] = sig;

    // ---- Set-dueling update ----
    // Only update PSEL for leader sets, on miss, and only if not streaming
    if (!hit && !streaming) {
        if (leader == 1) { // SRRIP leader
            if (psel < 1023) psel++;
        }
        else if (leader == 2) { // BRRIP leader
            if (psel > 0) psel--;
        }
    }

    // ---- Periodic decay of SHiP and dead counters ----
    if (access_counter % DECAY_PERIOD == 0) {
        for (uint32_t i = 0; i < SHIP_TABLE_SIZE; ++i)
            if (ship_table[i].reuse_counter > 0)
                ship_table[i].reuse_counter--;
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            for (uint32_t w = 0; w < LLC_WAYS; ++w)
                if (dead_counter[s][w] > 0)
                    dead_counter[s][w]--;
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
    int dead_lines = 0;
    for (int i = 0; i < LLC_SETS; ++i)
        for (int j = 0; j < LLC_WAYS; ++j)
            if (dead_counter[i][j] >= 2) dead_lines++;
    std::cout << "HSDS Policy: Hybrid SHiP-Deadblock Streaming" << std::endl;
    std::cout << "High-reuse PC signatures: " << high_reuse_pcs << "/" << SHIP_TABLE_SIZE << std::endl;
    std::cout << "Streaming sets (score>=2): " << streaming_sets << "/" << LLC_SETS << std::endl;
    std::cout << "Dead lines (dead_counter>=2): " << dead_lines << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "Final PSEL: " << psel << " (0=BRRIP, 1023=SRRIP)" << std::endl;
}

// Print periodic (heartbeat) statistics
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
            if (dead_counter[i][j] >= 2) dead_lines++;
    std::cout << "High-reuse PC signatures (heartbeat): " << high_reuse_pcs << "/" << SHIP_TABLE_SIZE << std::endl;
    std::cout << "Streaming sets (heartbeat): " << streaming_sets << "/" << LLC_SETS << std::endl;
    std::cout << "Dead lines (heartbeat): " << dead_lines << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "PSEL (heartbeat): " << psel << " (0=BRRIP, 1023=SRRIP)" << std::endl;
}