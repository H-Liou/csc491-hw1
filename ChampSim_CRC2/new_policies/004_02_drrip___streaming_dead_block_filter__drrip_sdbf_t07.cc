#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- DRRIP metadata ---
uint8_t rrpv[LLC_SETS][LLC_WAYS]; // 2 bits per block
#define PSEL_BITS 10
uint16_t psel; // 10-bit global selector

#define SD_LEADER_SETS 32
#define SD_LEADER_MASK (SD_LEADER_SETS-1)
uint8_t sd_leader_type[LLC_SETS]; // 0: SRRIP, 1: BRRIP; only for leader sets

// --- Streaming Detector ---
struct StreamDetect {
    uint64_t last_addr;
    int64_t last_delta;
    uint8_t stream_count; // 0–15
    uint8_t is_streaming; // 1 if monotonic detected
};
StreamDetect streamdet[LLC_SETS];

// --- Dead-block filter (reuse bit) ---
uint8_t dead_bit[LLC_SETS][LLC_WAYS]; // 1 bit per block

// --- Periodic decay ---
uint64_t access_counter = 0;

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv));
    memset(dead_bit, 0, sizeof(dead_bit));
    memset(streamdet, 0, sizeof(streamdet));
    psel = (1 << (PSEL_BITS-1));
    // Assign leader sets for SRRIP and BRRIP
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        sd_leader_type[s] = (s & SD_LEADER_MASK) < (SD_LEADER_SETS/2) ? 0 : 1;
}

// --- Streaming detector update ---
inline void update_stream_detector(uint32_t set, uint64_t paddr) {
    uint64_t last_addr = streamdet[set].last_addr;
    int64_t delta = int64_t(paddr) - int64_t(last_addr);
    if (last_addr != 0 && (delta == streamdet[set].last_delta) && (delta != 0)) {
        if (streamdet[set].stream_count < 15) streamdet[set].stream_count++;
    } else {
        streamdet[set].stream_count = 0;
    }
    streamdet[set].last_delta = delta;
    streamdet[set].last_addr = paddr;
    streamdet[set].is_streaming = (streamdet[set].stream_count >= 6) ? 1 : 0;
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

// --- Dead-block periodic decay ---
inline void dead_block_decay() {
    if ((access_counter & 0xFFF) == 0) { // every 4096 LLC accesses
        for (uint32_t set = 0; set < LLC_SETS; ++set)
            for (uint32_t way = 0; way < LLC_WAYS; ++way)
                dead_bit[set][way] = 0; // decay all dead bits
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
    access_counter++;
    if ((access_counter & 0xFFF) == 0) dead_block_decay();

    // Update streaming detector
    update_stream_detector(set, paddr);

    // On hit: promote block, mark as reused
    if (hit) {
        rrpv[set][way] = 0;
        dead_bit[set][way] = 0; // not dead
        return;
    }

    // --- Streaming dead-block filter bypass ---
    if (streamdet[set].is_streaming) {
        // If block being replaced was not reused (dead), then bypass allocation
        if (dead_bit[set][way]) {
            // Bypass: do not allocate (simulate by setting high RRPV)
            rrpv[set][way] = 3;
            return;
        }
        // Insert at distant RRPV for streaming phases
        rrpv[set][way] = 3;
        dead_bit[set][way] = 1; // predict dead until proven reused
        return;
    }

    // --- DRRIP insertion depth ---
    uint8_t ins_rrpv = 2; // default SRRIP
    // Set-dueling leaders
    if ((set & SD_LEADER_MASK) < (SD_LEADER_SETS/2)) {
        // SRRIP leader: always ins_rrpv=2
    } else if ((set & SD_LEADER_MASK) < SD_LEADER_SETS) {
        // BRRIP leader: ins_rrpv=3 with 1/32 probability; else 2
        ins_rrpv = ((rand() & 0x1F) == 0) ? 3 : 2;
    } else {
        // Follower sets: use psel
        ins_rrpv = (psel >= (1 << (PSEL_BITS-1))) ? 2 : (((rand() & 0x1F) == 0) ? 3 : 2);
    }
    rrpv[set][way] = ins_rrpv;
    dead_bit[set][way] = 1; // predict dead until reused

    // DRRIP set-dueling psel update
    if ((set & SD_LEADER_MASK) < SD_LEADER_SETS) {
        if (hit) {
            if (sd_leader_type[set] == 0 && psel < ((1 << PSEL_BITS)-1)) psel++; // SRRIP leader hit
            else if (sd_leader_type[set] == 1 && psel > 0) psel--; // BRRIP leader hit
        }
    }
}

// --- Print end-of-sim stats ---
void PrintStats() {
    int streaming_sets = 0, dead_blocks = 0, total_blocks = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s) {
        if (streamdet[s].is_streaming) streaming_sets++;
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            if (dead_bit[s][w]) dead_blocks++;
            total_blocks++;
        }
    }
    std::cout << "DRRIP-SDBF Policy: DRRIP + Streaming Dead-Block Filter" << std::endl;
    std::cout << "Streaming sets detected: " << streaming_sets << "/" << LLC_SETS << std::endl;
    std::cout << "Dead blocks flagged: " << dead_blocks << "/" << total_blocks << std::endl;
    std::cout << "DRRIP PSEL value: " << psel << std::endl;
}

void PrintStats_Heartbeat() {
    int dead_blocks = 0, total_blocks = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            if (dead_bit[s][w]) dead_blocks++;
            total_blocks++;
        }
    std::cout << "Dead blocks (heartbeat): " << dead_blocks << "/" << total_blocks << std::endl;
}