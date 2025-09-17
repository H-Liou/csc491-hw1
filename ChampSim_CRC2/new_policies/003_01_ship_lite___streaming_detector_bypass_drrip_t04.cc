#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// RRIP definitions
#define MAX_RRPV 3 // 2 bits per line

// DRRIP PSEL and set-dueling
#define PSEL_BITS 10
#define PSEL_MAX ((1 << PSEL_BITS) - 1)
#define SD_LEADER_SETS 32 // 16 SRRIP, 16 BRRIP

// SHiP-lite definitions
#define SHIP_ENTRIES 8192 // 8K entries
#define SHIP_CTR_MAX 3    // 2 bits per entry
#define SIGNATURE_BITS 6  // 6 bits per entry

// Streaming detector: per-set last address, delta, and streaming flag
struct STREAM_DETECTOR {
    uint64_t last_addr;
    int64_t last_delta;
    uint8_t stream_count; // saturating counter, 0-7
    bool is_streaming;
};
std::vector<STREAM_DETECTOR> stream_detector(LLC_SETS);

// Per-line metadata: RRPV and SHiP signature
struct LINE_REPL_META {
    uint8_t rrpv;         // 2 bits
    uint16_t signature;   // 6 bits
};

std::vector<LINE_REPL_META> repl_meta(LLC_SETS * LLC_WAYS);

uint8_t SHIP_table[SHIP_ENTRIES]; // 6-bit signature index, 2-bit outcome

// DRRIP PSEL
uint16_t PSEL = PSEL_MAX / 2;

// SRRIP/BRRIP leader sets
std::vector<uint8_t> is_srrip_leader(LLC_SETS, 0);
std::vector<uint8_t> is_brrip_leader(LLC_SETS, 0);

// Helper: Hash PC to signature
inline uint16_t get_signature(uint64_t PC) {
    return (PC ^ (PC >> 16)) & (SHIP_ENTRIES - 1);
}

void InitReplacementState() {
    for (uint32_t s = 0; s < LLC_SETS; ++s) {
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            uint32_t idx = s * LLC_WAYS + w;
            repl_meta[idx].rrpv = MAX_RRPV;
            repl_meta[idx].signature = 0;
        }
        stream_detector[s].last_addr = 0;
        stream_detector[s].last_delta = 0;
        stream_detector[s].stream_count = 0;
        stream_detector[s].is_streaming = false;
    }
    memset(SHIP_table, 1, sizeof(SHIP_table)); // Neutral outcome
    PSEL = PSEL_MAX / 2;

    // Set leader sets for DRRIP set-dueling
    for (uint32_t i = 0; i < SD_LEADER_SETS; ++i) {
        is_srrip_leader[i] = 1;
        is_brrip_leader[LLC_SETS - 1 - i] = 1;
    }
}

uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // RRIP victim selection
    uint32_t base = set * LLC_WAYS;
    while (true) {
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            if (repl_meta[base + w].rrpv == MAX_RRPV) {
                return w;
            }
        }
        // Increment RRPV (aging)
        for (uint32_t w = 0; w < LLC_WAYS; ++w)
            if (repl_meta[base + w].rrpv < MAX_RRPV)
                repl_meta[base + w].rrpv++;
    }
}

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
    uint32_t idx = set * LLC_WAYS + way;
    // --- SHiP-lite signature extraction ---
    uint16_t signature = get_signature(PC);

    // --- Streaming Detector Update ---
    STREAM_DETECTOR& sd = stream_detector[set];
    int64_t delta = (sd.last_addr == 0) ? 0 : (int64_t)paddr - (int64_t)sd.last_addr;
    bool same_delta = (delta != 0) && (delta == sd.last_delta);

    // Update streaming counter
    if (same_delta) {
        if (sd.stream_count < 7) sd.stream_count++;
    } else {
        if (sd.stream_count > 0) sd.stream_count--;
    }
    sd.is_streaming = (sd.stream_count >= 5); // streaming detected if counter high
    sd.last_delta = delta;
    sd.last_addr = paddr;

    // On cache hit
    if (hit) {
        // SHiP outcome update
        if (SHIP_table[signature] < SHIP_CTR_MAX)
            SHIP_table[signature]++;
        repl_meta[idx].rrpv = 0; // Promote on hit
    } else {
        // DRRIP insertion policy selection
        bool srrip_mode = false, brrip_mode = false;
        if (is_srrip_leader[set]) srrip_mode = true;
        if (is_brrip_leader[set]) brrip_mode = true;
        if (!srrip_mode && !brrip_mode)
            srrip_mode = (PSEL >= (PSEL_MAX / 2));

        // SHiP insertion depth
        uint8_t ship_outcome = SHIP_table[signature];
        uint8_t insert_rrpv = MAX_RRPV;
        if (ship_outcome >= 2) {
            insert_rrpv = 0; // likely reusable
        } else if (ship_outcome == 1) {
            insert_rrpv = 2; // moderate
        } else {
            insert_rrpv = MAX_RRPV; // dead-on-arrival
        }

        // Streaming detector: if streaming, bypass or insert at distant RRPV
        if (sd.is_streaming) {
            // For streaming, insert at MAX_RRPV (quick eviction)
            insert_rrpv = MAX_RRPV;
        }

        // Apply DRRIP mode
        if (srrip_mode) {
            // SRRIP: insert at 2 (long term), unless SHiP/streaming says otherwise
            if (insert_rrpv > 2) insert_rrpv = 2;
        } else if (brrip_mode) {
            // BRRIP: insert at 3 (short term) ~1/32 times, otherwise at 2
            if (rand() % 32 == 0) insert_rrpv = MAX_RRPV;
            else if (insert_rrpv > 2) insert_rrpv = 2;
        }

        repl_meta[idx].rrpv = insert_rrpv;
        repl_meta[idx].signature = signature;
    }

    // PSEL update: only on leader sets
    if (is_srrip_leader[set]) {
        if (hit && type == 0 && PSEL < PSEL_MAX) PSEL++;
    }
    if (is_brrip_leader[set]) {
        if (hit && type == 0 && PSEL > 0) PSEL--;
    }
}

void PrintStats() {
    std::cout << "SHiP-Lite + Streaming Detector Bypass DRRIP stats\n";
}

void PrintStats_Heartbeat() {
    // No-op
}