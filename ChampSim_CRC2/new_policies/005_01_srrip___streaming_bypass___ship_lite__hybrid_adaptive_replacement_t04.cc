#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// SRRIP definitions
#define RRPV_BITS 2
#define RRPV_MAX ((1 << RRPV_BITS) - 1) // 3

// SHiP-lite definitions
#define SHIP_ENTRIES 6144 // 6K entries
#define SHIP_CTR_MAX 3    // 2 bits per entry
#define SIGNATURE_BITS 6  // 6 bits per entry

// Streaming detector
#define STREAM_DELTA_THRESHOLD 4
#define STREAM_CNT_MAX 3 // 2 bits

struct LINE_REPL_META {
    uint8_t rrpv;        // 2 bits
    uint16_t signature;  // 6 bits
};

std::vector<LINE_REPL_META> repl_meta(LLC_SETS * LLC_WAYS);

// SHiP-lite table: 6K entries, 2 bits per entry
uint8_t SHIP_table[SHIP_ENTRIES];

// Streaming detector: 2 bits per set
std::vector<uint8_t> streaming_cnt(LLC_SETS, 0);
std::vector<uint64_t> last_addr(LLC_SETS, 0);

inline uint16_t get_signature(uint64_t PC) {
    return (PC ^ (PC >> 16)) & (SHIP_ENTRIES - 1);
}

void InitReplacementState() {
    for (uint32_t s = 0; s < LLC_SETS; ++s) {
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            uint32_t idx = s * LLC_WAYS + w;
            repl_meta[idx].rrpv = RRPV_MAX;
            repl_meta[idx].signature = 0;
        }
        streaming_cnt[s] = 0;
        last_addr[s] = 0;
    }
    memset(SHIP_table, 1, sizeof(SHIP_table)); // Neutral outcome
}

// Find victim: choose block with RRPV==MAX, else increment all RRPV and retry
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    uint32_t base = set * LLC_WAYS;
    while (true) {
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            if (repl_meta[base + w].rrpv == RRPV_MAX)
                return w;
        }
        // Increment all RRPVs
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            if (repl_meta[base + w].rrpv < RRPV_MAX)
                repl_meta[base + w].rrpv++;
        }
    }
}

// Streaming detector: update per set
void update_streaming_detector(uint32_t set, uint64_t paddr) {
    uint64_t last = last_addr[set];
    int64_t delta = (int64_t)paddr - (int64_t)last;
    if (last != 0 && (delta == 64 || delta == -64)) { // 64B line stride
        if (streaming_cnt[set] < STREAM_CNT_MAX)
            streaming_cnt[set]++;
    } else {
        if (streaming_cnt[set] > 0)
            streaming_cnt[set]--;
    }
    last_addr[set] = paddr;
}

// Is set streaming?
inline bool is_streaming(uint32_t set) {
    return streaming_cnt[set] >= STREAM_DELTA_THRESHOLD;
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
    uint16_t signature = get_signature(PC);

    // Update streaming detector
    update_streaming_detector(set, paddr);

    // On hit: SHiP outcome update, set RRPV to 0 (MRU)
    if (hit) {
        if (SHIP_table[signature] < SHIP_CTR_MAX)
            SHIP_table[signature]++;
        repl_meta[idx].rrpv = 0;
        repl_meta[idx].signature = signature;
        return;
    }

    // On miss: check streaming
    if (is_streaming(set)) {
        // Streaming detected: bypass (do not insert, set RRPV=MAX so it will be replaced soon)
        repl_meta[idx].rrpv = RRPV_MAX;
        repl_meta[idx].signature = signature;
        return;
    }

    // SHiP-lite prediction
    bool ship_dead = (SHIP_table[signature] == 0);

    // Insert: predicted dead blocks at RRPV=MAX, reusable blocks at RRPV=0, else RRPV=2 (middle)
    if (ship_dead) {
        repl_meta[idx].rrpv = RRPV_MAX;
    } else if (SHIP_table[signature] >= 2) {
        repl_meta[idx].rrpv = 0;
    } else {
        repl_meta[idx].rrpv = 2;
    }
    repl_meta[idx].signature = signature;
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "SRRIP + Streaming Bypass + SHiP-Lite stats\n";
}

void PrintStats_Heartbeat() {
    // No-op
}