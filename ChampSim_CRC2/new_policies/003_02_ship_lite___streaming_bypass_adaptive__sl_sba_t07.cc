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
#define SHIP_SIG_ENTRIES 1024
uint8_t ship_counter[SHIP_SIG_ENTRIES]; // 2 bits per entry

// --- Streaming Detector metadata ---
struct StreamDetect {
    uint64_t last_addr;
    int8_t last_delta;
    uint8_t stream_count;  // counts consecutive monotonic accesses
    uint8_t is_streaming;  // 1 if streaming detected
};
StreamDetect streamdet[LLC_SETS];

// --- RRIP metadata ---
uint8_t rrpv[LLC_SETS][LLC_WAYS]; // 2 bits per block

// --- Initialization ---
void InitReplacementState() {
    memset(ship_counter, 1, sizeof(ship_counter));
    memset(rrpv, 3, sizeof(rrpv));
    for (uint32_t s = 0; s < LLC_SETS; ++s) {
        streamdet[s].last_addr = 0;
        streamdet[s].last_delta = 0;
        streamdet[s].stream_count = 0;
        streamdet[s].is_streaming = 0;
    }
}

// --- SHiP signature helper ---
inline uint16_t get_signature(uint64_t PC) {
    return (PC ^ (PC >> 2)) & ((1 << SHIP_SIG_BITS) - 1);
}

// --- Streaming Detector Update ---
inline void update_stream_detector(uint32_t set, uint64_t paddr) {
    uint64_t last_addr = streamdet[set].last_addr;
    int64_t delta = int64_t(paddr) - int64_t(last_addr);

    if (last_addr != 0 && (delta == streamdet[set].last_delta) && (delta != 0)) {
        // monotonic stride repeated
        if (streamdet[set].stream_count < 15) streamdet[set].stream_count++;
    } else {
        streamdet[set].stream_count = 0;
    }
    streamdet[set].last_delta = delta;
    streamdet[set].last_addr = paddr;

    // Streaming detected if stride repeats 6+ times
    streamdet[set].is_streaming = (streamdet[set].stream_count >= 6) ? 1 : 0;
}

// --- Find victim ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Standard SRRIP victim selection
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (!current_set[way].valid)
            return way;

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
    uint16_t sig = get_signature(PC);

    // Update streaming detector
    update_stream_detector(set, paddr);

    // On hit: update SHiP, promote block
    if (hit) {
        if (ship_counter[sig] < 3) ship_counter[sig]++;
        rrpv[set][way] = 0;
        return;
    }

    // --- Streaming Bypass/Insertion Control ---
    if (streamdet[set].is_streaming) {
        // Streaming: insert mostly at distant RRPV; with 1/16 probability, bypass (no allocation)
        if ((rand() & 0xF) == 0) {
            // Bypass: mark block as invalid (simulate not allocating)
            rrpv[set][way] = 3;
            return;
        } else {
            rrpv[set][way] = 3;
        }
        // Decay SHiP counter slightly on streaming to clear old bias
        if (ship_counter[sig] > 0) ship_counter[sig]--;
        return;
    }

    // --- SHiP-Lite guided insertion ---
    uint8_t ins_rrpv = (ship_counter[sig] >= 2) ? 1 : 3;
    rrpv[set][way] = ins_rrpv;

    // Decay SHiP counter on miss (to age out old PCs with no recent reuse)
    if (ship_counter[sig] > 0) ship_counter[sig]--;
}

// --- Stats ---
void PrintStats() {
    // Print streaming set count
    int stream_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (streamdet[s].is_streaming) stream_sets++;
    std::cout << "SL-SBA Policy: SHiP-Lite + Streaming Bypass Adaptive" << std::endl;
    std::cout << "Streaming sets detected: " << stream_sets << "/" << LLC_SETS << std::endl;
}

void PrintStats_Heartbeat() {
    // Optionally print SHiP counter statistics
    int reused = 0, total = 0;
    for (int i = 0; i < SHIP_SIG_ENTRIES; ++i) {
        if (ship_counter[i] >= 2) reused++;
        total++;
    }
    std::cout << "SHiP signatures with reuse: " << reused << "/" << total << std::endl;
}