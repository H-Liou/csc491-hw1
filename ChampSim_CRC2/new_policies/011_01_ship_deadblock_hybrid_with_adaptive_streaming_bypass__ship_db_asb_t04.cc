#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- SRRIP/BRRIP set-dueling ---
#define NUM_LEADER_SETS 64
#define PSEL_BITS 10
uint16_t psel;
uint8_t leader_set_type[LLC_SETS]; // 0: SRRIP, 1: BRRIP, 2: follower

// --- SHiP-lite Metadata ---
#define SIG_BITS 6
#define SHIP_CTR_BITS 2
uint8_t ship_signature[LLC_SETS][LLC_WAYS]; // 6-bit per block
uint8_t ship_ctr[LLC_SETS][LLC_WAYS];       // 2-bit per block

// --- RRIP Metadata ---
uint8_t rrpv[LLC_SETS][LLC_WAYS]; // 2 bits per block

// --- Dead-block Approximation Metadata ---
uint8_t deadblock[LLC_SETS][LLC_WAYS]; // 1 bit per block

// --- Streaming Detector Metadata ---
#define STREAM_HIST_LEN 4
uint64_t stream_addr_hist[LLC_SETS][STREAM_HIST_LEN]; // last 4 addresses per set
uint8_t stream_hist_ptr[LLC_SETS]; // circular pointer per set

// --- Streaming Detector Thresholds ---
#define STREAM_DETECT_COUNT 3 // at least 3 matching strides
#define STREAM_BYPASS_RRPV 3  // insert at distant RRPV (or bypass)

// --- Dead-block periodic decay ---
#define DB_DECAY_PERIOD 8192
uint64_t db_decay_epoch = 0;

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv));
    memset(ship_signature, 0, sizeof(ship_signature));
    memset(ship_ctr, 1, sizeof(ship_ctr)); // Start at weak reuse
    memset(deadblock, 0, sizeof(deadblock));
    memset(stream_addr_hist, 0, sizeof(stream_addr_hist));
    memset(stream_hist_ptr, 0, sizeof(stream_hist_ptr));
    psel = (1 << (PSEL_BITS - 1));
    for (uint32_t s = 0; s < LLC_SETS; ++s) {
        if (s < NUM_LEADER_SETS / 2) leader_set_type[s] = 0; // SRRIP
        else if (s < NUM_LEADER_SETS) leader_set_type[s] = 1; // BRRIP
        else leader_set_type[s] = 2; // follower
    }
    db_decay_epoch = 0;
}

// --- PC Signature hashing ---
inline uint8_t get_signature(uint64_t PC) {
    return static_cast<uint8_t>((PC ^ (PC >> 7)) & ((1 << SIG_BITS) - 1));
}

// --- Streaming Detector: returns true if streaming detected ---
bool is_streaming(uint32_t set, uint64_t paddr) {
    uint8_t ptr = stream_hist_ptr[set];
    stream_addr_hist[set][ptr] = paddr;
    stream_hist_ptr[set] = (ptr + 1) % STREAM_HIST_LEN;
    if (ptr < STREAM_HIST_LEN - 1)
        return false; // not enough history yet

    // Compute strides
    int64_t strides[STREAM_HIST_LEN - 1];
    for (int i = 1; i < STREAM_HIST_LEN; ++i)
        strides[i - 1] = (int64_t)stream_addr_hist[set][i] - (int64_t)stream_addr_hist[set][i - 1];

    // Count matching strides
    int match = 0;
    for (int i = 1; i < STREAM_HIST_LEN - 1; ++i)
        if (strides[i] == strides[0]) match++;

    // If stride is regular and nonzero, likely streaming
    return (match >= STREAM_DETECT_COUNT - 1 && strides[0] != 0);
}

// --- Dead-block periodic decay ---
void deadblock_decay() {
    db_decay_epoch++;
    if ((db_decay_epoch % DB_DECAY_PERIOD) == 0) {
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            for (uint32_t w = 0; w < LLC_WAYS; ++w)
                deadblock[s][w] = 0;
    }
}

// --- Victim selection ---
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

    // Dead-block victim preference
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (deadblock[set][way])
            return way;

    // RRIP victim selection
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
    // Periodic dead-block decay
    deadblock_decay();

    uint8_t sig = get_signature(PC);

    // On hit: promote block, increment reuse counter, mark not dead
    if (hit) {
        rrpv[set][way] = 0;
        if (ship_ctr[set][way] < 3) ship_ctr[set][way]++;
        deadblock[set][way] = 0;
        return;
    }

    // --- Streaming detector ---
    bool streaming = is_streaming(set, paddr);

    // --- SRRIP/BRRIP set-dueling: choose insertion depth ---
    uint8_t insertion_rrpv = 2; // SRRIP default (insert at RRPV=2)
    if (leader_set_type[set] == 0) { // SRRIP leader
        insertion_rrpv = 2;
    } else if (leader_set_type[set] == 1) { // BRRIP leader
        insertion_rrpv = (rand() % 32 == 0) ? 2 : 3; // RRPV=2 with 1/32 probability
    } else { // follower
        insertion_rrpv = (psel >= (1 << (PSEL_BITS - 1))) ? 2 : ((rand() % 32 == 0) ? 2 : 3);
    }

    // --- SHiP bias: if strong reuse, override and insert at MRU ---
    if (ship_ctr[set][way] >= 2)
        insertion_rrpv = 0;

    // --- Dead-block bias: if block is dead, insert at distant RRPV ---
    if (deadblock[set][way])
        insertion_rrpv = 3;

    // --- Streaming bypass: if streaming detected, insert at distant RRPV or bypass ---
    if (streaming)
        insertion_rrpv = STREAM_BYPASS_RRPV;

    rrpv[set][way] = insertion_rrpv;
    ship_signature[set][way] = sig;
    ship_ctr[set][way] = 1;
    deadblock[set][way] = 0; // reset on insertion

    // --- Mark victim as dead if not reused ---
    if (!hit)
        deadblock[set][way] = 1;

    // --- PSEL update ---
    if (leader_set_type[set] == 0) { // SRRIP leader
        if (hit) { if (psel < ((1 << PSEL_BITS) - 1)) psel++; }
        else { if (psel > 0) psel--; }
    } else if (leader_set_type[set] == 1) { // BRRIP leader
        if (hit) { if (psel > 0) psel--; }
        else { if (psel < ((1 << PSEL_BITS) - 1)) psel++; }
    }
}

// --- Print end-of-simulation statistics ---
void PrintStats() {
    int strong_reuse = 0, total_blocks = 0, dead_blocks = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s) {
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            if (ship_ctr[s][w] == 3) strong_reuse++;
            if (deadblock[s][w]) dead_blocks++;
            total_blocks++;
        }
    }
    std::cout << "SHiP-DB-ASB Policy: SHiP-lite + Dead-block + Adaptive Streaming Bypass" << std::endl;
    std::cout << "Blocks with strong reuse (SHIP ctr==3): " << strong_reuse << "/" << total_blocks << std::endl;
    std::cout << "Dead blocks: " << dead_blocks << "/" << total_blocks << std::endl;
    std::cout << "PSEL value: " << psel << std::endl;
}

// --- Print periodic (heartbeat) statistics ---
void PrintStats_Heartbeat() {
    int strong_reuse = 0, total_blocks = 0, dead_blocks = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s) {
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            if (ship_ctr[s][w] == 3) strong_reuse++;
            if (deadblock[s][w]) dead_blocks++;
            total_blocks++;
        }
    }
    std::cout << "Strong reuse blocks (heartbeat): " << strong_reuse << "/" << total_blocks
              << ", Dead blocks: " << dead_blocks << "/" << total_blocks << std::endl;
}