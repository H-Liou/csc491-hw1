#include <vector>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// ---- DIP Set-dueling (LIP vs. BIP) ----
#define LEADER_SETS 64
uint8_t leader_flags[LLC_SETS]; // 0: normal, 1: LIP leader, 2: BIP leader
uint16_t psel; // 10 bits (0..1023)

// ---- SHiP-lite: Signature table ----
#define SHIP_SIG_BITS 6
#define SHIP_TABLE_SIZE 1024 // 6 bits
struct SHIPEntry {
    uint8_t reuse_counter; // 2 bits
};
SHIPEntry ship_table[SHIP_TABLE_SIZE];

// ---- Per-line PC signatures ----
uint16_t line_sig[LLC_SETS][LLC_WAYS]; // 6 bits per line

// ---- Dead-block bit per line ----
uint8_t dead_bit[LLC_SETS][LLC_WAYS]; // 1 bit per line

// ---- Streaming detector: per-set stride evidence ----
uint64_t last_addr[LLC_SETS];      // previous address per set
int8_t stride_score[LLC_SETS];     // signed, accumulates stride hits [-4,4]
uint8_t stream_flag[LLC_SETS];     // 1=streaming detected

// ---- Other bookkeeping ----
uint64_t access_counter = 0;
#define DECAY_PERIOD 100000

void InitReplacementState() {
    memset(leader_flags, 0, sizeof(leader_flags));
    memset(ship_table, 1, sizeof(ship_table));
    memset(line_sig, 0, sizeof(line_sig));
    memset(dead_bit, 0, sizeof(dead_bit));
    memset(last_addr, 0, sizeof(last_addr));
    memset(stride_score, 0, sizeof(stride_score));
    memset(stream_flag, 0, sizeof(stream_flag));
    access_counter = 0;

    // Assign leader sets: evenly spaced, first 32 LIP, next 32 BIP
    for (uint32_t i = 0; i < LEADER_SETS; ++i) {
        uint32_t lip_set = (i * (LLC_SETS / (2 * LEADER_SETS)));
        uint32_t bip_set = lip_set + (LLC_SETS / 2);
        leader_flags[lip_set] = 1; // LIP leader
        leader_flags[bip_set] = 2; // BIP leader
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

    // Next, prefer dead block (dead_bit==1)
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (dead_bit[set][way] == 1)
            return way;

    // Otherwise, LRU (lowest timestamp, or way 0 as fallback)
    return 0;
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
    int8_t score = stride_score[set];
    if (last == 0) {
        last_addr[set] = paddr;
        stride_score[set] = 0;
        stream_flag[set] = 0;
    } else {
        uint64_t delta = (paddr > last) ? (paddr - last) : (last - paddr);
        if (delta == 64 || delta == 128) { // 1-2 block stride
            if (score < 4) stride_score[set]++;
        } else {
            if (score > -4) stride_score[set]--;
        }
        last_addr[set] = paddr;
        if (stride_score[set] >= 3) stream_flag[set] = 1;
        else if (stride_score[set] <= -2) stream_flag[set] = 0;
    }
    bool streaming = (stream_flag[set] == 1);

    // ---- SHiP signature extraction ----
    uint16_t sig = (uint16_t)((PC >> 2) & 0x3F); // 6 bits
    uint16_t ship_idx = sig;
    line_sig[set][way] = sig;

    // ---- SHiP outcome update ----
    if (hit) {
        // On hit, increment SHiP counter, mark not-dead
        if (ship_table[ship_idx].reuse_counter < 3)
            ship_table[ship_idx].reuse_counter++;
        dead_bit[set][way] = 0;
    } else {
        // On miss/evict, penalize previous signature and mark dead
        uint16_t evict_sig = line_sig[set][way];
        if (ship_table[evict_sig].reuse_counter > 0)
            ship_table[evict_sig].reuse_counter--;
        dead_bit[set][way] = 1;
    }

    // ---- DIP insertion depth selection ----
    uint8_t leader = leader_flags[set];
    bool use_bip = false;
    if (leader == 1)
        use_bip = false; // LIP leader
    else if (leader == 2)
        use_bip = true;  // BIP leader
    else
        use_bip = (psel >= 512);

    uint8_t insertion_way = 0; // default LIP: insert at LRU
    if (use_bip) {
        // BIP: insert at MRU with low probability (1/32), else at LRU
        insertion_way = ((rand() % 32) == 0) ? (LLC_WAYS - 1) : 0;
    }

    // ---- SHiP bias: high-reuse signature inserts at MRU
    if (ship_table[ship_idx].reuse_counter >= 2)
        insertion_way = LLC_WAYS - 1;

    // ---- Streaming detector: streaming sets bypass fill with probability
    if (streaming && (rand() % 2 == 0)) {
        // If streaming is detected, bypass fill half the time
        dead_bit[set][way] = 1;
        return; // do not fill
    }

    // Fill block: mark not-dead, set PC signature
    dead_bit[set][way] = 0;
    line_sig[set][way] = sig;

    // ---- DIP set-dueling update ----
    // Only update PSEL for leader sets, on miss
    if (!hit) {
        if (leader == 1 && !streaming) { // LIP leader
            if (psel < 1023) psel++;
        }
        else if (leader == 2 && !streaming) { // BIP leader
            if (psel > 0) psel--;
        }
    }

    // ---- Periodic decay of SHiP reuse counters ----
    if (access_counter % DECAY_PERIOD == 0) {
        for (uint32_t i = 0; i < SHIP_TABLE_SIZE; ++i)
            if (ship_table[i].reuse_counter > 0)
                ship_table[i].reuse_counter--;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    int high_reuse_pcs = 0;
    for (int i = 0; i < SHIP_TABLE_SIZE; ++i)
        if (ship_table[i].reuse_counter >= 2) high_reuse_pcs++;
    int streaming_sets = 0;
    for (int i = 0; i < LLC_SETS; ++i)
        if (stream_flag[i] == 1) streaming_sets++;
    int dead_blocks = 0;
    for (int i = 0; i < LLC_SETS; ++i)
        for (int j = 0; j < LLC_WAYS; ++j)
            if (dead_bit[i][j] == 1) dead_blocks++;
    std::cout << "DSDS-Hybrid Policy: DIP-SHiP Dead-Streaming Hybrid" << std::endl;
    std::cout << "High-reuse PC signatures: " << high_reuse_pcs << "/" << SHIP_TABLE_SIZE << std::endl;
    std::cout << "Streaming sets (flag==1): " << streaming_sets << "/" << LLC_SETS << std::endl;
    std::cout << "Dead blocks: " << dead_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "Final PSEL: " << psel << " (0=LIP, 1023=BIP)" << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    int high_reuse_pcs = 0;
    for (int i = 0; i < SHIP_TABLE_SIZE; ++i)
        if (ship_table[i].reuse_counter >= 2) high_reuse_pcs++;
    int streaming_sets = 0;
    for (int i = 0; i < LLC_SETS; ++i)
        if (stream_flag[i] == 1) streaming_sets++;
    int dead_blocks = 0;
    for (int i = 0; i < LLC_SETS; ++i)
        for (int j = 0; j < LLC_WAYS; ++j)
            if (dead_bit[i][j] == 1) dead_blocks++;
    std::cout << "High-reuse PC signatures (heartbeat): " << high_reuse_pcs << "/" << SHIP_TABLE_SIZE << std::endl;
    std::cout << "Streaming sets (heartbeat): " << streaming_sets << "/" << LLC_SETS << std::endl;
    std::cout << "Dead blocks (heartbeat): " << dead_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "PSEL (heartbeat): " << psel << " (0=LIP, 1023=BIP)" << std::endl;
}