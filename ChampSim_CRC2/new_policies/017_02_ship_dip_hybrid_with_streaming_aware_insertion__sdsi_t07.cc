#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// ----- DIP Metadata -----
#define PSEL_BITS 10
uint16_t PSEL = (1 << (PSEL_BITS - 1)); // 10-bit PSEL selector

#define NUM_LEADER_SETS 32
uint8_t is_lip_leader[LLC_SETS]; // 1 if LIP leader, 2 if BIP leader, 0 otherwise

// ----- SHiP-lite Metadata -----
#define SIG_BITS 6
uint8_t ship_signature[LLC_SETS][LLC_WAYS]; // 6-bit per block
uint8_t ship_ctr[LLC_SETS][LLC_WAYS];       // 2-bit per block

// ----- LRU Stack Position (for LIP) -----
uint8_t lru_stack[LLC_SETS][LLC_WAYS]; // 4 bits per block (0=MRU, 15=LRU)

// ----- Streaming Detector Metadata -----
#define STREAM_HIST_LEN 4
uint64_t stream_addr_hist[LLC_SETS][STREAM_HIST_LEN];
uint8_t stream_hist_ptr[LLC_SETS];
uint8_t stream_detected[LLC_SETS];

// ----- Initialization -----
void InitReplacementState() {
    memset(ship_signature, 0, sizeof(ship_signature));
    memset(ship_ctr, 1, sizeof(ship_ctr));
    memset(lru_stack, 0, sizeof(lru_stack));
    memset(stream_addr_hist, 0, sizeof(stream_addr_hist));
    memset(stream_hist_ptr, 0, sizeof(stream_hist_ptr));
    memset(stream_detected, 0, sizeof(stream_detected));
    memset(is_lip_leader, 0, sizeof(is_lip_leader));

    // Select leader sets: evenly spaced
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i) {
        uint32_t lip_leader_set = (i * LLC_SETS) / (2 * NUM_LEADER_SETS);
        uint32_t bip_leader_set = lip_leader_set + LLC_SETS / 2;
        is_lip_leader[lip_leader_set] = 1;
        is_lip_leader[bip_leader_set % LLC_SETS] = 2;
    }

    PSEL = (1 << (PSEL_BITS - 1));
}

// ----- PC Signature hashing -----
inline uint8_t get_signature(uint64_t PC) {
    return static_cast<uint8_t>((PC ^ (PC >> 7)) & ((1 << SIG_BITS) - 1));
}

// ----- Streaming Detector: returns true if streaming detected -----
bool update_streaming(uint32_t set, uint64_t paddr) {
    uint8_t ptr = stream_hist_ptr[set];
    stream_addr_hist[set][ptr] = paddr;
    stream_hist_ptr[set] = (ptr + 1) % STREAM_HIST_LEN;
    if (ptr < STREAM_HIST_LEN - 1)
        return false; // not enough history yet
    int64_t ref_delta = (int64_t)stream_addr_hist[set][1] - (int64_t)stream_addr_hist[set][0];
    int match = 0;
    for (int i = 2; i < STREAM_HIST_LEN; ++i) {
        int64_t d = (int64_t)stream_addr_hist[set][i] - (int64_t)stream_addr_hist[set][i-1];
        if (d == ref_delta) match++;
    }
    stream_detected[set] = (match >= STREAM_HIST_LEN - 2) ? 1 : 0;
    return stream_detected[set];
}

// ----- LRU Stack Management -----
void update_lru(uint32_t set, uint32_t accessed_way) {
    uint8_t old_stack = lru_stack[set][accessed_way];
    // Move all blocks with stack < old_stack up by one
    for (uint32_t way = 0; way < LLC_WAYS; ++way) {
        if (lru_stack[set][way] < old_stack)
            lru_stack[set][way]++;
    }
    lru_stack[set][accessed_way] = 0; // MRU
}

// ----- Victim selection -----
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

    // Find LRU block (largest lru_stack)
    uint32_t victim = 0;
    uint8_t max_stack = lru_stack[set][0];
    for (uint32_t way = 1; way < LLC_WAYS; ++way) {
        if (lru_stack[set][way] > max_stack) {
            victim = way;
            max_stack = lru_stack[set][way];
        }
    }
    return victim;
}

// ----- Update replacement state -----
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
    uint8_t sig = get_signature(PC);

    // --- Streaming detector ---
    bool streaming = update_streaming(set, paddr);

    // --- SHiP update ---
    if (hit) {
        // Promote to MRU
        update_lru(set, way);
        if (ship_ctr[set][way] < 3) ship_ctr[set][way]++;
        return;
    }

    // On miss: SHiP counter decay
    if (ship_ctr[set][way] > 0) ship_ctr[set][way]--;

    // --- DIP insertion depth selection ---
    uint8_t insert_pos = LLC_WAYS - 1; // Default LIP: insert at LRU

    // If leader set, set insertion policy
    if (is_lip_leader[set] == 1) {
        insert_pos = LLC_WAYS - 1; // LIP: always LRU
    } else if (is_lip_leader[set] == 2) {
        insert_pos = (rand() % 32 == 0) ? 0 : (LLC_WAYS - 1); // BIP: 1/32 MRU, else LRU
    } else {
        // Follower sets use PSEL
        insert_pos = (PSEL >= (1 << (PSEL_BITS - 1))) ? (LLC_WAYS - 1)
                                                      : ((rand() % 32 == 0) ? 0 : (LLC_WAYS - 1));
    }

    // --- SHiP bias: strong reuse (ctr>=2) → insert at MRU
    if (ship_ctr[set][way] >= 2)
        insert_pos = 0;

    // --- Streaming-aware: during streaming, always insert at LRU unless SHiP strong reuse
    if (streaming && ship_ctr[set][way] < 2)
        insert_pos = LLC_WAYS - 1;

    // --- Insert block ---
    // Set LRU stack position
    lru_stack[set][way] = insert_pos;
    // Update others
    for (uint32_t i = 0; i < LLC_WAYS; ++i) {
        if (i == way) continue;
        if (lru_stack[set][i] < insert_pos)
            lru_stack[set][i]++;
    }

    ship_signature[set][way] = sig;
    ship_ctr[set][way] = 1; // weak reuse on fill

    // --- DIP PSEL update ---
    // On leader sets, update PSEL based on hit/miss
    if (is_lip_leader[set] == 1) {
        if (hit && PSEL < ((1 << PSEL_BITS) - 1)) PSEL++;
        else if (!hit && PSEL > 0) PSEL--;
    }
    if (is_lip_leader[set] == 2) {
        if (hit && PSEL > 0) PSEL--;
        else if (!hit && PSEL < ((1 << PSEL_BITS) - 1)) PSEL++;
    }
}

// ----- Print end-of-simulation statistics -----
void PrintStats() {
    int strong_reuse = 0, total_blocks = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            if (ship_ctr[s][w] == 3) strong_reuse++;
            total_blocks++;
        }
    std::cout << "SDSI Policy: SHiP-DIP Hybrid + Streaming-aware Insertion" << std::endl;
    std::cout << "Blocks with strong reuse (SHIP ctr==3): " << strong_reuse << "/" << total_blocks << std::endl;
    std::cout << "PSEL value: " << PSEL << std::endl;
}

// ----- Print periodic (heartbeat) statistics -----
void PrintStats_Heartbeat() {
    int strong_reuse = 0, total_blocks = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            if (ship_ctr[s][w] == 3) strong_reuse++;
            total_blocks++;
        }
    std::cout << "Strong reuse blocks (heartbeat): " << strong_reuse << "/" << total_blocks << std::endl;
    std::cout << "PSEL (heartbeat): " << PSEL << std::endl;
}