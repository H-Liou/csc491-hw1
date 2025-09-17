#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- DRRIP set-dueling ---
#define NUM_LEADER_SETS 64
#define PSEL_BITS 10
uint16_t psel;
uint8_t leader_set_type[LLC_SETS]; // 0: SRRIP, 1: BRRIP, 2: follower

// --- SHiP-lite Metadata ---
#define SIG_BITS 5
#define SHIP_CTR_BITS 2
uint8_t ship_signature[LLC_SETS][LLC_WAYS]; // 5-bit per block
uint8_t ship_ctr[LLC_SETS][LLC_WAYS];       // 2-bit per block

// --- RRIP Metadata ---
uint8_t rrpv[LLC_SETS][LLC_WAYS]; // 2 bits per block

// --- Streaming Detector Metadata ---
#define STREAM_HIST_LEN 4
uint64_t stream_last_addr[LLC_SETS];
int32_t stream_delta_hist[LLC_SETS][STREAM_HIST_LEN];
uint8_t stream_hist_ptr[LLC_SETS];
uint8_t stream_score[LLC_SETS]; // 2 bits per set

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv));
    memset(ship_signature, 0, sizeof(ship_signature));
    memset(ship_ctr, 1, sizeof(ship_ctr)); // Start at weak reuse
    psel = (1 << (PSEL_BITS - 1));
    for (uint32_t s = 0; s < LLC_SETS; ++s) {
        if (s < NUM_LEADER_SETS / 2) leader_set_type[s] = 0; // SRRIP
        else if (s < NUM_LEADER_SETS) leader_set_type[s] = 1; // BRRIP
        else leader_set_type[s] = 2; // follower
        stream_last_addr[s] = 0;
        memset(stream_delta_hist[s], 0, sizeof(stream_delta_hist[s]));
        stream_hist_ptr[s] = 0;
        stream_score[s] = 0;
    }
}

// --- PC Signature hashing ---
inline uint8_t get_signature(uint64_t PC) {
    return static_cast<uint8_t>((PC ^ (PC >> 5)) & ((1 << SIG_BITS) - 1));
}

// --- Streaming Detector Update ---
inline void update_stream_detector(uint32_t set, uint64_t paddr) {
    int32_t delta = (stream_last_addr[set] == 0) ? 0 : (int32_t)(paddr - stream_last_addr[set]);
    stream_delta_hist[set][stream_hist_ptr[set]] = delta;
    stream_hist_ptr[set] = (stream_hist_ptr[set] + 1) % STREAM_HIST_LEN;
    stream_last_addr[set] = paddr;

    // Check if all recent deltas are equal and nonzero (streaming)
    int32_t first = stream_delta_hist[set][0];
    bool streaming = (first != 0);
    for (int i = 1; i < STREAM_HIST_LEN; ++i)
        if (stream_delta_hist[set][i] != first || stream_delta_hist[set][i] == 0)
            streaming = false;

    // Update score (2-bit saturating counter)
    if (streaming) {
        if (stream_score[set] < 3) stream_score[set]++;
    } else {
        if (stream_score[set] > 0) stream_score[set]--;
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
    update_stream_detector(set, paddr);

    uint8_t sig = get_signature(PC);

    // On hit: promote block, increment reuse counter
    if (hit) {
        rrpv[set][way] = 0;
        if (ship_ctr[set][way] < 3) ship_ctr[set][way]++;
        return;
    }

    // --- Streaming bypass logic: if streaming detected, insert at distant RRPV or bypass ---
    bool streaming = (stream_score[set] >= 2);
    if (streaming) {
        // If SHiP predicts no reuse, bypass (simulate not caching)
        if (ship_ctr[set][way] == 0) {
            rrpv[set][way] = 3;
            ship_signature[set][way] = sig;
            ship_ctr[set][way] = 0;
            return;
        }
    }

    // --- DRRIP set-dueling: choose insertion depth ---
    uint8_t insertion_rrpv = 2; // SRRIP default
    if (leader_set_type[set] == 0) { // SRRIP leader
        insertion_rrpv = 2;
    } else if (leader_set_type[set] == 1) { // BRRIP leader
        insertion_rrpv = (rand() % 32 == 0) ? 0 : 2; // MRU with 1/32 probability
    } else { // follower
        insertion_rrpv = (psel >= (1 << (PSEL_BITS - 1))) ? 2 : ((rand() % 32 == 0) ? 0 : 2);
    }

    // --- SHiP bias: if strong reuse, override and insert at MRU ---
    if (ship_ctr[set][way] >= 2)
        insertion_rrpv = 0;

    // --- Streaming bias: if streaming, force distant RRPV unless SHiP strong reuse ---
    if (streaming && ship_ctr[set][way] < 2)
        insertion_rrpv = 3;

    rrpv[set][way] = insertion_rrpv;
    ship_signature[set][way] = sig;
    ship_ctr[set][way] = 1;

    // --- DRRIP PSEL update ---
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
    int streaming_sets = 0, strong_reuse = 0, total_blocks = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s) {
        if (stream_score[s] >= 2) streaming_sets++;
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            if (ship_ctr[s][w] == 3) strong_reuse++;
            total_blocks++;
        }
    }
    std::cout << "DRRIP-SHiP-SD Policy: DRRIP set-dueling + SHiP-lite + Streaming Detector" << std::endl;
    std::cout << "Sets with streaming detected: " << streaming_sets << "/" << LLC_SETS << std::endl;
    std::cout << "Blocks with strong reuse (SHIP ctr==3): " << strong_reuse << "/" << total_blocks << std::endl;
    std::cout << "PSEL value: " << psel << std::endl;
}

// --- Print periodic (heartbeat) statistics ---
void PrintStats_Heartbeat() {
    int strong_reuse = 0, total_blocks = 0, streaming_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s) {
        if (stream_score[s] >= 2) streaming_sets++;
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            if (ship_ctr[s][w] == 3) strong_reuse++;
            total_blocks++;
        }
    }
    std::cout << "Strong reuse blocks (heartbeat): " << strong_reuse << "/" << total_blocks << std::endl;
    std::cout << "Streaming sets (heartbeat): " << streaming_sets << "/" << LLC_SETS << std::endl;
}