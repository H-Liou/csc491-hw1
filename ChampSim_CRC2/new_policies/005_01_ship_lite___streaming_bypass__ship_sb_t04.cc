#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- SHiP-lite metadata ---
#define SHIP_SIG_BITS 6
#define SHIP_TABLE_ENTRIES 4096 // 12 bits index
#define SHIP_COUNTER_BITS 2
uint8_t ship_table[SHIP_TABLE_ENTRIES]; // 2 bits per signature

uint8_t rrpv[LLC_SETS][LLC_WAYS]; // 2 bits per block
uint16_t ship_sig[LLC_SETS][LLC_WAYS]; // 6 bits per block

// --- Streaming Detector ---
struct StreamDetect {
    uint64_t last_addr;
    int64_t last_delta;
    uint8_t stream_count; // 0–31
    uint8_t is_streaming; // 1 if monotonic detected
};
StreamDetect streamdet[LLC_SETS];

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv));
    memset(ship_sig, 0, sizeof(ship_sig));
    memset(ship_table, 1, sizeof(ship_table)); // initialize to weak reuse
    memset(streamdet, 0, sizeof(streamdet));
}

// --- Streaming detector update ---
inline void update_stream_detector(uint32_t set, uint64_t paddr) {
    uint64_t last_addr = streamdet[set].last_addr;
    int64_t delta = int64_t(paddr) - int64_t(last_addr);
    if (last_addr != 0 && (delta == streamdet[set].last_delta) && (delta != 0)) {
        if (streamdet[set].stream_count < 31) streamdet[set].stream_count++;
    } else {
        streamdet[set].stream_count = 0;
    }
    streamdet[set].last_delta = delta;
    streamdet[set].last_addr = paddr;
    streamdet[set].is_streaming = (streamdet[set].stream_count >= 8) ? 1 : 0;
}

// --- SHiP signature hash ---
inline uint16_t get_ship_sig(uint64_t PC) {
    // Simple CRC or xor hash for 6 bits
    return champsim_crc2(PC, 0) & ((1 << SHIP_SIG_BITS)-1);
}

// --- SHiP table index ---
inline uint16_t get_ship_index(uint16_t sig) {
    // Direct index, or hash if needed
    return sig; // 6 bits, so 64 entries, but we use 4096 for less aliasing
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
    // Standard SRRIP victim selection
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
    // Update streaming detector
    update_stream_detector(set, paddr);

    // Compute signature
    uint16_t sig = get_ship_sig(PC);
    uint16_t idx = (sig ^ set) & (SHIP_TABLE_ENTRIES-1);

    // On hit: promote block, mark as reused
    if (hit) {
        rrpv[set][way] = 0;
        // Update SHiP outcome counter (max 3)
        if (ship_table[idx] < 3) ship_table[idx]++;
        return;
    }

    // --- Streaming bypass logic ---
    if (streamdet[set].is_streaming) {
        // If signature is weak (counter==0), bypass allocation (simulate by setting high RRPV)
        if (ship_table[idx] == 0) {
            rrpv[set][way] = 3;
            ship_sig[set][way] = sig;
            return;
        }
        // Else: insert at distant RRPV (streaming phase)
        rrpv[set][way] = 3;
        ship_sig[set][way] = sig;
        return;
    }

    // --- SHiP-based insertion depth ---
    uint8_t ins_rrpv = (ship_table[idx] >= 2) ? 0 : 2; // strong reuse: MRU; else SRRIP default
    rrpv[set][way] = ins_rrpv;
    ship_sig[set][way] = sig;

    // On eviction, update SHiP outcome counter (if not reused)
    if (!hit) {
        uint16_t victim_sig = ship_sig[set][way];
        uint16_t victim_idx = (victim_sig ^ set) & (SHIP_TABLE_ENTRIES-1);
        // If block was not reused (i.e., not promoted to MRU before eviction), decrement
        if (ship_table[victim_idx] > 0) ship_table[victim_idx]--;
    }
}

// --- Print end-of-sim stats ---
void PrintStats() {
    int streaming_sets = 0, strong_sig = 0, total_sig = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (streamdet[s].is_streaming) streaming_sets++;
    for (uint32_t i = 0; i < SHIP_TABLE_ENTRIES; ++i) {
        if (ship_table[i] >= 2) strong_sig++;
        total_sig++;
    }
    std::cout << "SHiP-SB Policy: SHiP-lite + Streaming Bypass" << std::endl;
    std::cout << "Streaming sets detected: " << streaming_sets << "/" << LLC_SETS << std::endl;
    std::cout << "Strong reuse signatures: " << strong_sig << "/" << total_sig << std::endl;
}

void PrintStats_Heartbeat() {
    int strong_sig = 0, total_sig = 0;
    for (uint32_t i = 0; i < SHIP_TABLE_ENTRIES; ++i) {
        if (ship_table[i] >= 2) strong_sig++;
        total_sig++;
    }
    std::cout << "Strong reuse signatures (heartbeat): " << strong_sig << "/" << total_sig << std::endl;
}