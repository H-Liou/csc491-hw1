#include <vector>
#include <cstdint>
#include <iostream>
#include <array>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// ---- RRIP Metadata ----
uint8_t rrpv[LLC_SETS][LLC_WAYS]; // 2 bits per block

// ---- Per-block PC signature (for SHiP-lite) ----
uint8_t pc_sig[LLC_SETS][LLC_WAYS]; // 8 bits per block (index into SHiP table)

// ---- SHiP-lite: 256-entry table, 6 bits per outcome counter ----
#define SHIP_TABLE_SIZE 256
std::array<uint8_t, SHIP_TABLE_SIZE> ship_ctr; // 6 bits per entry

// ---- Streaming Detector: per-set 6 bits ----
uint8_t stream_score[LLC_SETS]; // 0–63, higher = more streaming

// ---- Set-dueling for streaming bypass ----
#define NUM_LEADER_SETS 64
#define PSEL_BITS 10
uint16_t PSEL = 512;
uint8_t leader_set_type[NUM_LEADER_SETS]; // 0: streaming bypass, 1: normal
std::vector<uint32_t> leader_sets;

// Helper: is this set a leader set? Returns 0=bypass, 1=normal, 2=follower
uint8_t GetSetType(uint32_t set) {
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i)
        if (leader_sets[i] == set)
            return leader_set_type[i];
    return 2; // Follower
}

// Helper: get SHiP-lite index for a PC
inline uint8_t PC_sig(uint64_t PC) {
    // Use lower 8 bits of CRC32 of PC, for better distribution
    return champsim_crc32(uint32_t(PC)) & 0xFF;
}

// Streaming detector: track address stride per set, increment score if monotonic
std::array<uint64_t, LLC_SETS> last_addr;
std::array<int64_t, LLC_SETS> last_stride;

// Initialize replacement state
void InitReplacementState() {
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            rrpv[set][way] = 2; // default distant
            pc_sig[set][way] = 0; // default signature
        }
        stream_score[set] = 0;
        last_addr[set] = 0;
        last_stride[set] = 0;
    }
    for (size_t i = 0; i < SHIP_TABLE_SIZE; ++i)
        ship_ctr[i] = 32; // neutral (max=63, min=0)
    // Leader sets: evenly spread
    leader_sets.clear();
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i) {
        uint32_t set = (i * LLC_SETS) / NUM_LEADER_SETS;
        leader_sets.push_back(set);
        leader_set_type[i] = (i < NUM_LEADER_SETS / 2) ? 0 : 1; // First half bypass, second half normal
    }
    PSEL = 512;
}

// Find victim in the set (classic RRIP)
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
    // Classic RRIP: look for RRPV==3
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
    // --- Streaming detector ---
    int64_t cur_stride = int64_t(paddr) - int64_t(last_addr[set]);
    if (last_addr[set] != 0) {
        // If stride matches previous, grow score (bounded)
        if (cur_stride == last_stride[set] && cur_stride != 0) {
            if (stream_score[set] < 63) stream_score[set]++;
        } else {
            if (stream_score[set] > 0) stream_score[set]--;
        }
    }
    last_addr[set] = paddr;
    last_stride[set] = cur_stride;

    // --- SHiP-lite: update outcome counter ---
    uint8_t sig = PC_sig(PC);
    if (hit) {
        if (ship_ctr[sig] < 63) ship_ctr[sig]++;
        rrpv[set][way] = 0; // protect reused block
    } else {
        if (ship_ctr[sig] > 0) ship_ctr[sig]--;
    }

    // --- Set-dueling: leader sets update PSEL (bypass vs normal) ---
    uint8_t set_type = GetSetType(set);
    if (!hit && set_type < 2) {
        if (set_type == 0) { // bypass leader miss: increment PSEL
            if (PSEL < ((1 << PSEL_BITS) - 1)) PSEL++;
        } else if (set_type == 1) { // normal leader miss: decrement PSEL
            if (PSEL > 0) PSEL--;
        }
    }

    // --- Insertion policy: combine SHiP-lite + streaming ---
    bool is_streaming = stream_score[set] >= 48;
    bool should_bypass = false;
    if (set_type == 0)      // bypass leader
        should_bypass = is_streaming;
    else if (set_type == 1) // normal leader
        should_bypass = false;
    else                    // follower
        should_bypass = (PSEL >= 512) ? is_streaming : false;

    // On cache miss: for streaming, either bypass or insert at distant
    if (!hit) {
        pc_sig[set][way] = sig;
        if (should_bypass) {
            // Streaming bypass: do NOT cache block (simulate by marking RRPV=3)
            rrpv[set][way] = 3;
        } else {
            // SHiP-lite: if outcome counter high, insert MRU; else distant
            rrpv[set][way] = (ship_ctr[sig] >= 32) ? 0 : 2;
        }
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    int streaming_sets = 0;
    int ship_hot = 0, ship_cold = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        if (stream_score[set] >= 48) streaming_sets++;
    for (size_t i = 0; i < SHIP_TABLE_SIZE; ++i) {
        if (ship_ctr[i] >= 48) ship_hot++;
        else if (ship_ctr[i] <= 16) ship_cold++;
    }
    std::cout << "SHiP-Lite + Streaming Detector Hybrid" << std::endl;
    std::cout << "Streaming sets (score>=48): " << streaming_sets << "/" << LLC_SETS << std::endl;
    std::cout << "SHiP hot signatures (ctr>=48): " << ship_hot << "/" << SHIP_TABLE_SIZE << std::endl;
    std::cout << "SHiP cold signatures (ctr<=16): " << ship_cold << "/" << SHIP_TABLE_SIZE << std::endl;
    std::cout << "PSEL: " << PSEL << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    int streaming_sets = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        if (stream_score[set] >= 48) streaming_sets++;
    std::cout << "Streaming sets (heartbeat): " << streaming_sets << "/" << LLC_SETS << std::endl;
}