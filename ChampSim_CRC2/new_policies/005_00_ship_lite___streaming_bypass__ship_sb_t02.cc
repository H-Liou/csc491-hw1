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
#define SHIP_SIG_ENTRIES 4096 // 12 bits index
struct SHIPEntry {
    uint8_t counter; // 2 bits: 0–3
};
SHIPEntry ship_table[SHIP_SIG_ENTRIES];

// Per-block PC signature
uint8_t block_sig[LLC_SETS][LLC_WAYS]; // 6 bits per block

// --- RRPV bits ---
uint8_t rrpv[LLC_SETS][LLC_WAYS]; // 2 bits per block

// --- Streaming detector ---
struct StreamDetect {
    uint64_t last_addr;
    int64_t last_delta;
    uint8_t stream_count; // 0–31
    uint8_t is_streaming; // 1 if monotonic detected
};
StreamDetect streamdet[LLC_SETS]; // 5 bits per set

// --- Initialization ---
void InitReplacementState() {
    memset(ship_table, 0, sizeof(ship_table));
    memset(block_sig, 0, sizeof(block_sig));
    memset(rrpv, 3, sizeof(rrpv));
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
    // Use lower bits of PC, CRC for mixing
    return champsim_crc2(PC) & (SHIP_SIG_ENTRIES - 1);
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

    // Compute PC signature
    uint16_t sig = get_ship_sig(PC);

    // On hit: promote block, update SHiP outcome
    if (hit) {
        rrpv[set][way] = 0;
        // If block's signature matches, increment outcome counter
        uint8_t sig_stored = block_sig[set][way];
        if (ship_table[sig_stored].counter < 3)
            ship_table[sig_stored].counter++;
        return;
    }

    // --- Streaming bypass logic ---
    if (streamdet[set].is_streaming) {
        // For streaming sets, bypass allocation for blocks whose PC signature is not known to be reusable
        if (ship_table[sig].counter == 0) {
            // Bypass: set RRPV to distant (simulate dead-on-arrival)
            rrpv[set][way] = 3;
            block_sig[set][way] = sig;
            return;
        }
        // Otherwise, insert at distant RRPV but track signature
        rrpv[set][way] = 3;
        block_sig[set][way] = sig;
        return;
    }

    // --- SHiP insertion depth ---
    // If PC signature outcome counter is high, insert at RRPV=0 (long-lived); else at RRPV=2 (short-lived)
    if (ship_table[sig].counter >= 2)
        rrpv[set][way] = 0;
    else
        rrpv[set][way] = 2;
    block_sig[set][way] = sig;

    // On eviction: update SHiP outcome counter
    uint8_t evict_sig = block_sig[set][way];
    if (!hit) {
        // If block was not reused (i.e., not hit before eviction), decrement outcome counter
        if (ship_table[evict_sig].counter > 0)
            ship_table[evict_sig].counter--;
    }
}

// --- Print end-of-sim stats ---
void PrintStats() {
    int streaming_sets = 0, reusable_sigs = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (streamdet[s].is_streaming) streaming_sets++;
    for (uint32_t i = 0; i < SHIP_SIG_ENTRIES; ++i)
        if (ship_table[i].counter >= 2) reusable_sigs++;
    std::cout << "SHiP-SB Policy: SHiP-lite + Streaming Bypass" << std::endl;
    std::cout << "Streaming sets detected: " << streaming_sets << "/" << LLC_SETS << std::endl;
    std::cout << "Reusable PC signatures: " << reusable_sigs << "/" << SHIP_SIG_ENTRIES << std::endl;
}

void PrintStats_Heartbeat() {
    int reusable_sigs = 0;
    for (uint32_t i = 0; i < SHIP_SIG_ENTRIES; ++i)
        if (ship_table[i].counter >= 2) reusable_sigs++;
    std::cout << "Reusable PC signatures (heartbeat): " << reusable_sigs << "/" << SHIP_SIG_ENTRIES << std::endl;
}