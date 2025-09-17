#include <vector>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- RRIP: 2-bit RRPV per block ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// --- SHiP-lite: 6-bit PC signature, 2-bit outcome counter ---
#define SHIP_SIG_BITS 6
#define SHIP_TABLE_SIZE 1024
uint8_t block_sig[LLC_SETS][LLC_WAYS];         // Per-block signature
uint8_t ship_counter[SHIP_TABLE_SIZE];         // 2-bit outcome counter

// --- DRRIP set-dueling ---
#define DUEL_LEADER_SETS 32
uint8_t is_sr_leader[LLC_SETS];                // 1 if SRRIP leader, 2 if BRRIP leader, 0 otherwise
uint16_t psel = 512;                           // 10-bit PSEL counter (range 0–1023)

// --- Streaming detector: per-set, 8 bits ---
// Detect monotonic address deltas (simple stride streaming)
uint64_t last_addr[LLC_SETS];
int8_t stream_score[LLC_SETS];                 // -8 to +8

// Initialize replacement state
void InitReplacementState() {
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            rrpv[set][way] = 2;
            block_sig[set][way] = 0;
        }
        last_addr[set] = 0;
        stream_score[set] = 0;
        is_sr_leader[set] = 0;
    }
    // Assign leader sets for set-dueling
    for (uint32_t i = 0; i < DUEL_LEADER_SETS; ++i) {
        is_sr_leader[i] = 1; // SRRIP leader
        is_sr_leader[LLC_SETS - 1 - i] = 2; // BRRIP leader
    }
    for (uint32_t i = 0; i < SHIP_TABLE_SIZE; ++i)
        ship_counter[i] = 1;
    psel = 512;
}

// Find victim in the set (RRIP)
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] < 3)
                ++rrpv[set][way];
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
    // --- SHiP signature extraction ---
    uint16_t sig = ((PC >> 2) ^ (set & 0x3F)) & ((1 << SHIP_SIG_BITS) - 1);

    // --- Streaming detector update ---
    int64_t delta = (int64_t)paddr - (int64_t)last_addr[set];
    if (delta == 64 || delta == -64) { // 64B stride streaming
        if (stream_score[set] < 8) stream_score[set]++;
    } else {
        if (stream_score[set] > -8) stream_score[set]--;
    }
    last_addr[set] = paddr;

    // --- SHiP outcome update ---
    uint16_t old_sig = block_sig[set][way];
    if (hit) {
        // Block reused: reward signature, set MRU
        if (ship_counter[old_sig] < 3) ship_counter[old_sig]++;
        rrpv[set][way] = 0;
    } else {
        // Block evicted: if not reused, decay signature
        if (ship_counter[old_sig] > 0) ship_counter[old_sig]--;
        // Insert new block: record signature
        block_sig[set][way] = sig;

        // --- Streaming bypass logic ---
        bool streaming = (stream_score[set] >= 6);

        // --- DRRIP insertion depth selection ---
        bool use_brrip = false;
        if (is_sr_leader[set] == 1) use_brrip = false; // SRRIP leader
        else if (is_sr_leader[set] == 2) use_brrip = true; // BRRIP leader
        else use_brrip = (psel < 512); // PSEL < 512: BRRIP, else SRRIP

        // --- SHiP insertion depth bias ---
        if (streaming) {
            // Streaming detected: bypass (insert at RRPV=3)
            rrpv[set][way] = 3;
        } else if (ship_counter[sig] >= 2) {
            // Hot signature: insert at MRU (RRPV=0)
            rrpv[set][way] = 0;
        } else {
            // Cold signature: use DRRIP baseline
            if (use_brrip) {
                // BRRIP: insert at RRPV=2 (long re-reference)
                rrpv[set][way] = 2;
            } else {
                // SRRIP: insert at RRPV=1 (medium re-reference)
                rrpv[set][way] = 1;
            }
        }

        // --- Set-dueling PSEL update ---
        if (is_sr_leader[set]) {
            if (hit && is_sr_leader[set] == 1 && psel < 1023) psel++;
            if (hit && is_sr_leader[set] == 2 && psel > 0) psel--;
        }
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    int hot_sig = 0, cold_sig = 0;
    for (int i = 0; i < SHIP_TABLE_SIZE; ++i) {
        if (ship_counter[i] >= 2) hot_sig++;
        else cold_sig++;
    }
    std::cout << "SHiP-DRRIP-SB: Hot signatures: " << hot_sig
              << " / " << SHIP_TABLE_SIZE << std::endl;
    std::cout << "SHiP-DRRIP-SB: Cold signatures: " << cold_sig << std::endl;
    std::cout << "SHiP-DRRIP-SB: Final PSEL: " << psel << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    int streaming_sets = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        if (stream_score[set] >= 6) streaming_sets++;
    std::cout << "SHiP-DRRIP-SB: Streaming sets: " << streaming_sets << std::endl;
}