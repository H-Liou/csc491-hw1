#include <vector>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- Per-block metadata ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];           // 2 bits per block
uint8_t pc_sig[LLC_SETS][LLC_WAYS];         // 6 bits per block (PC signature)

// --- SHiP-lite signature table ---
#define SHIP_SIG_BITS 6
#define SHIP_SIG_ENTRIES 1024                // 2^6 * 16 = 1024
uint8_t ship_ctr[SHIP_SIG_ENTRIES];          // 2 bits per entry

// --- Streaming detector: 2 bits/set (0: not streaming, 1: weak, 2: strong, 3: bypass) ---
uint8_t stream_state[LLC_SETS];              // 2 bits per set
uint64_t last_addr[LLC_SETS];                // last accessed block address per set

// Helper: get SHiP signature index
inline uint16_t SHIP_SIG_IDX(uint64_t PC) {
    // Use lower 6 bits XOR upper 6 bits for mix
    return ((PC & 0x3F) ^ ((PC >> 8) & 0x3F)) | 0;
}

// Initialize replacement state
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv));         // all blocks to distant
    memset(pc_sig, 0, sizeof(pc_sig));
    memset(ship_ctr, 1, sizeof(ship_ctr)); // neutral SHiP starting value
    memset(stream_state, 0, sizeof(stream_state));
    memset(last_addr, 0, sizeof(last_addr));
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
    // Streaming detector: in strong/bypass mode, always evict oldest (rrpv==3)
    if (stream_state[set] >= 2) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            rrpv[set][way] = 3;
        // Try again
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
    }
    // Otherwise, classic RRIP
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
    // --- Streaming detector update ---
    uint64_t block_addr = paddr >> 6; // block granularity
    uint64_t last = last_addr[set];
    if (last != 0) {
        int64_t delta = block_addr - last;
        if (delta == 1) {
            // Monotonic forward: promote streaming state up to strong
            if (stream_state[set] < 3) stream_state[set]++;
        } else if (delta != 0) {
            // Non-monotonic: demote streaming state
            if (stream_state[set] > 0) stream_state[set]--;
        }
        // If streaming state saturates at 3, treat as bypass candidate
    }
    last_addr[set] = block_addr;

    // --- SHiP signature ---
    uint8_t sig = SHIP_SIG_IDX(PC);

    // --- On hit: update SHiP counter positively, protect block ---
    if (hit) {
        pc_sig[set][way] = sig;
        uint16_t idx = (sig << 4) | (way & 0xF); // spread signatures a bit
        if (ship_ctr[idx] < 3) ship_ctr[idx]++;
        rrpv[set][way] = 0; // protect
    } else {
        // On miss: update SHiP counter negatively for the victim
        uint8_t v_sig = pc_sig[set][way];
        uint16_t v_idx = (v_sig << 4) | (way & 0xF);
        if (ship_ctr[v_idx] > 0) ship_ctr[v_idx]--;
        pc_sig[set][way] = sig;
    }

    // --- Insertion depth ---
    uint8_t ins_rrpv = 2; // default mid
    if (stream_state[set] == 3) {
        // Detected streaming: insert at most distant (or bypass)
        ins_rrpv = 3;
    } else if (stream_state[set] >= 2) {
        // Strong streaming: insert at distant
        ins_rrpv = 3;
    } else {
        // Use SHiP prediction
        uint16_t idx = (sig << 4) | (way & 0xF);
        if (ship_ctr[idx] >= 2)
            ins_rrpv = 0; // predicted reusable: protect
        else if (ship_ctr[idx] == 1)
            ins_rrpv = 2;
        else
            ins_rrpv = 3; // predicted non-reusable: distant
    }
    if (!hit)
        rrpv[set][way] = ins_rrpv;

    // --- Periodic SHiP counter decay (every 8192 fills) ---
    static uint64_t fill_count = 0;
    fill_count++;
    if ((fill_count & 0x1FFF) == 0) {
        for (uint32_t i = 0; i < SHIP_SIG_ENTRIES; ++i)
            if (ship_ctr[i] > 1)
                ship_ctr[i]--;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    int protected = 0, distant = 0, streaming_sets = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (rrpv[set][way] == 0) protected++;
            if (rrpv[set][way] == 3) distant++;
        }
        if (stream_state[set] >= 2) streaming_sets++;
    }
    std::cout << "SHiP-lite + Streaming Detector Hybrid" << std::endl;
    std::cout << "Protected blocks: " << protected << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "Distant blocks: " << distant << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "Streaming sets (strong/bypass): " << streaming_sets << "/" << LLC_SETS << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    int protected = 0, distant = 0, streaming_sets = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (rrpv[set][way] == 0) protected++;
            if (rrpv[set][way] == 3) distant++;
        }
        if (stream_state[set] >= 2) streaming_sets++;
    }
    std::cout << "Protected blocks (heartbeat): " << protected << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "Distant blocks (heartbeat): " << distant << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "Streaming sets (heartbeat): " << streaming_sets << "/" << LLC_SETS << std::endl;
}