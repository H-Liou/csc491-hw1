#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- SHiP-lite: Per-set, 64-entry signature table, 2-bit outcome counters ---
#define SHIP_SIG_BITS 6
#define SHIP_SIG_ENTRIES (1 << SHIP_SIG_BITS) // 64 per set
uint8_t ship_sig_table[LLC_SETS][SHIP_SIG_ENTRIES]; // 2 bits per entry

// Per-block: store signature for update on eviction
uint8_t block_signature[LLC_SETS][LLC_WAYS]; // 6 bits per block

// --- Streaming detector: Per-set, 2-bit saturating counter, last address ---
uint64_t last_addr[LLC_SETS];
uint8_t stream_ctr[LLC_SETS]; // 2 bits per set

#define STREAM_THRESHOLD 3

// --- RRIP: 2-bit RRPV per block ---
uint8_t rrpv[LLC_SETS][LLC_WAYS]; // 2 bits per block

// --- Initialization ---
void InitReplacementState() {
    memset(ship_sig_table, 1, sizeof(ship_sig_table)); // neutral prediction
    memset(block_signature, 0, sizeof(block_signature));
    memset(rrpv, 3, sizeof(rrpv));
    memset(stream_ctr, 0, sizeof(stream_ctr));
    memset(last_addr, 0, sizeof(last_addr));
}

// --- Streaming detector update ---
inline void update_streaming(uint32_t set, uint64_t paddr) {
    uint64_t last = last_addr[set];
    uint64_t delta = (last == 0) ? 0 : (paddr > last ? paddr - last : last - paddr);
    // Detect monotonic stride: delta == block size (64B), or small stride
    if (last != 0 && (delta == 64 || delta == 128)) {
        if (stream_ctr[set] < 3) stream_ctr[set]++;
    } else {
        if (stream_ctr[set] > 0) stream_ctr[set]--;
    }
    last_addr[set] = paddr;
}

// --- SHiP-lite signature extraction ---
inline uint8_t get_signature(uint64_t PC) {
    // Use lower SHIP_SIG_BITS of CRC32(PC)
    return champsim_crc32(PC) & (SHIP_SIG_ENTRIES - 1);
}

// --- Find victim: RRIP ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Standard RRIP victim selection
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] < 3)
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
    // Update streaming detector
    update_streaming(set, paddr);

    // --- SHiP-lite: get signature and outcome counter ---
    uint8_t sig = get_signature(PC);
    uint8_t outcome = ship_sig_table[set][sig];

    // --- Streaming detector: if streaming detected, consider bypass ---
    bool streaming = (stream_ctr[set] >= STREAM_THRESHOLD);

    // --- Insertion/bypass logic ---
    uint8_t ins_rrpv = 2; // default: SRRIP insertion

    // If streaming and SHiP predicts dead (counter == 0), bypass (insert at RRPV=3)
    if (streaming && outcome == 0) {
        ins_rrpv = 3; // likely dead-on-arrival
    } else if (outcome >= 2) {
        ins_rrpv = 0; // high reuse, insert at RRPV=0
    } else if (outcome == 1) {
        ins_rrpv = 2; // moderate reuse
    } else {
        ins_rrpv = 3; // predicted dead
    }

    // On hit, promote to RRPV=0
    if (hit) {
        rrpv[set][way] = 0;
        // Update SHiP outcome counter: increment saturating
        if (ship_sig_table[set][sig] < 3) ship_sig_table[set][sig]++;
    } else {
        rrpv[set][way] = ins_rrpv;
        // Save signature for future update on eviction
        block_signature[set][way] = sig;
    }

    // On eviction (if not hit), update SHiP outcome counter for victim block
    if (!hit) {
        uint8_t victim_sig = block_signature[set][way];
        // If block was not reused (RRPV==3 on eviction), decrement counter
        if (rrpv[set][way] == 3) {
            if (ship_sig_table[set][victim_sig] > 0) ship_sig_table[set][victim_sig]--;
        }
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "SHiP-Lite + Streaming Bypass Hybrid: Final statistics." << std::endl;
    uint32_t streaming_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (stream_ctr[s] >= STREAM_THRESHOLD)
            streaming_sets++;
    std::cout << "Sets with streaming detected: " << streaming_sets << "/" << LLC_SETS << std::endl;
    // Optionally print SHiP table stats
    uint32_t high_reuse = 0, dead_pred = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        for (uint32_t i = 0; i < SHIP_SIG_ENTRIES; ++i) {
            if (ship_sig_table[s][i] >= 2) high_reuse++;
            if (ship_sig_table[s][i] == 0) dead_pred++;
        }
    std::cout << "SHiP signatures: high reuse=" << high_reuse << ", dead=" << dead_pred << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Optionally print streaming set count and SHiP table summary
}