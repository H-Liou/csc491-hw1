#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// SHiP-lite definitions
#define SHIP_ENTRIES 8192 // 8K entries
#define SHIP_CTR_MAX 3    // 2 bits per entry
#define SIGNATURE_BITS 6  // 6 bits per line

// Streaming detector definitions
#define STREAM_WINDOW 4   // 4-entry address delta window
#define STREAM_THRESH 3   // saturating counter threshold

struct LINE_REPL_META {
    uint8_t rrpv;         // 2 bits
    uint16_t signature;   // 6 bits
};

std::vector<LINE_REPL_META> repl_meta(LLC_SETS * LLC_WAYS);

uint8_t SHIP_table[SHIP_ENTRIES]; // 2 bits per entry

// Per-set streaming detector
struct STREAM_DETECTOR {
    uint64_t last_addr[STREAM_WINDOW];
    uint8_t ptr;
    int64_t last_delta;
    uint8_t stream_ctr; // saturating counter
};

std::vector<STREAM_DETECTOR> stream_meta(LLC_SETS);

// Helper: Hash PC to signature
inline uint16_t get_signature(uint64_t PC) {
    return (PC ^ (PC >> 16)) & (SHIP_ENTRIES - 1);
}

// Helper: Compute address delta
inline int64_t addr_delta(uint64_t a, uint64_t b) {
    return (int64_t)a - (int64_t)b;
}

void InitReplacementState() {
    for (uint32_t s = 0; s < LLC_SETS; ++s) {
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            uint32_t idx = s * LLC_WAYS + w;
            repl_meta[idx].rrpv = 3; // distant
            repl_meta[idx].signature = 0;
        }
        // Streaming detector init
        for (int i = 0; i < STREAM_WINDOW; ++i)
            stream_meta[s].last_addr[i] = 0;
        stream_meta[s].ptr = 0;
        stream_meta[s].last_delta = 0;
        stream_meta[s].stream_ctr = 0;
    }
    memset(SHIP_table, 1, sizeof(SHIP_table)); // Neutral outcome
}

// Find victim in the set: SRRIP
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    uint32_t base = set * LLC_WAYS;
    // SRRIP: look for RRPV==3
    while (true) {
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            if (repl_meta[base + w].rrpv == 3)
                return w;
        }
        // Increment all RRPVs
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            if (repl_meta[base + w].rrpv < 3)
                repl_meta[base + w].rrpv++;
        }
    }
}

// Streaming detector update
void update_stream_detector(uint32_t set, uint64_t paddr) {
    STREAM_DETECTOR &sd = stream_meta[set];
    uint64_t prev_addr = sd.last_addr[sd.ptr];
    int64_t delta = addr_delta(paddr, prev_addr);

    // Update window
    sd.last_addr[sd.ptr] = paddr;
    sd.ptr = (sd.ptr + 1) % STREAM_WINDOW;

    // Streaming: monotonic delta (same sign, similar stride)
    if (prev_addr != 0) {
        if (sd.last_delta != 0 && (delta * sd.last_delta > 0) && (std::abs(delta) == std::abs(sd.last_delta))) {
            if (sd.stream_ctr < STREAM_THRESH) sd.stream_ctr++;
        } else {
            if (sd.stream_ctr > 0) sd.stream_ctr--;
        }
        sd.last_delta = delta;
    }
}

// Is streaming detected?
bool is_streaming(uint32_t set) {
    return stream_meta[set].stream_ctr >= STREAM_THRESH;
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
    uint32_t idx = set * LLC_WAYS + way;
    uint16_t signature = get_signature(PC);

    // Streaming detector update
    update_stream_detector(set, paddr);

    // On hit
    if (hit) {
        // SHiP outcome update
        if (SHIP_table[signature] < SHIP_CTR_MAX)
            SHIP_table[signature]++;
        repl_meta[idx].signature = signature;
        repl_meta[idx].rrpv = 0; // promote to MRU
    } else {
        // SHiP prediction
        bool ship_dead = (SHIP_table[signature] == 0);

        // Streaming detection
        bool stream = is_streaming(set);

        // Final insertion RRPV
        uint8_t insert_rrpv = 2; // default: intermediate
        if (stream) {
            insert_rrpv = 3; // streaming: distant (or bypass if all lines are RRPV==3)
        } else if (ship_dead) {
            insert_rrpv = 3; // predicted dead: distant
        } else if (SHIP_table[signature] >= 2) {
            insert_rrpv = 0; // proven reuse: MRU
        }

        repl_meta[idx].signature = signature;
        repl_meta[idx].rrpv = insert_rrpv;
    }

    // On eviction: SHiP outcome update
    if (!hit) {
        uint32_t victim_idx = set * LLC_WAYS + GetVictimInSet(cpu, set, nullptr, PC, paddr, type);
        uint16_t victim_sig = repl_meta[victim_idx].signature;
        if (SHIP_table[victim_sig] > 0)
            SHIP_table[victim_sig]--;
    }
}

void PrintStats() {
    std::cout << "SRRIP + Streaming Detector + SHiP-Lite Hybrid stats\n";
}

void PrintStats_Heartbeat() {
    // No-op
}