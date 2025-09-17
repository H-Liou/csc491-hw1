#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- SHiP-lite parameters ---
#define SIG_BITS 6            // 6-bit PC signature
#define SIG_TABLE_SIZE 2048   // Signature table entries
#define OUTCOME_BITS 2        // 2-bit saturating counter

// --- Dead-block approximation ---
#define DEAD_BITS 1           // 1-bit per-line dead/live indicator
#define DECAY_INTERVAL 100000 // Decay dead/live bits every N fills

// --- Metadata structures ---
struct LineMeta {
    uint8_t rrpv;  // 2 bits
    uint8_t sig;   // 6 bits
    bool live;     // 1 bit (dead-block approx)
};

struct SignatureEntry {
    uint8_t outcome; // 2 bits (0 = dead, 3 = live)
};

LineMeta line_meta[LLC_SETS][LLC_WAYS];
SignatureEntry sig_table[SIG_TABLE_SIZE];

// --- Global state ---
uint64_t fill_count = 0;

// --- Helper: PC signature hash ---
uint8_t get_sig(uint64_t PC) {
    // Simple 6-bit hash from PC
    return (champsim_crc2(PC, 0) ^ (PC >> 2)) & ((1 << SIG_BITS) - 1);
}

// --- Initialization ---
void InitReplacementState() {
    memset(line_meta, 0, sizeof(line_meta));
    memset(sig_table, 0, sizeof(sig_table));
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            line_meta[set][way].rrpv = 3; // distant for RRIP
    fill_count = 0;
}

// --- Victim selection: RRIP with dead-block bias ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Prefer to evict dead lines (live==false), else RRIP victim
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (!line_meta[set][way].live)
            return way;

    // RRIP victim: minimum RRPV==3
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (line_meta[set][way].rrpv == 3)
                return way;
        // Increment all RRPVs
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (line_meta[set][way].rrpv < 3)
                line_meta[set][way].rrpv++;
    }
    return 0;
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
    fill_count++;

    // 1. PC signature and SHiP-lite outcome counter
    uint8_t sig = get_sig(PC);
    line_meta[set][way].sig = sig;
    SignatureEntry &entry = sig_table[sig];

    // 2. Dead-block approximation: bump live bit on hit
    if (hit) {
        line_meta[set][way].rrpv = 0; // promote to MRU
        line_meta[set][way].live = true;
        // Train signature as "live"
        if (entry.outcome < 3) entry.outcome++;
    } else {
        // On fill: use SHiP-lite outcome to set RRPV and live bit
        if (entry.outcome == 0) {
            // Predicted dead: bypass or insert distant
            line_meta[set][way].rrpv = 3;
            line_meta[set][way].live = false;
        } else if (entry.outcome == 1) {
            // Weakly dead: insert distant
            line_meta[set][way].rrpv = 3;
            line_meta[set][way].live = false;
        } else if (entry.outcome == 2) {
            // Weakly live: insert at middle
            line_meta[set][way].rrpv = 2;
            line_meta[set][way].live = true;
        } else {
            // Strongly live: insert MRU
            line_meta[set][way].rrpv = 0;
            line_meta[set][way].live = true;
        }
    }

    // 3. Train SHiP-lite "dead" on eviction (victim_addr)
    // (Find the evicted line's signature, decrement if not reused)
    // To avoid complex lookup, assume we train only on lines that were not hit before eviction
    // This is approximated via live==false
    if (!hit && !line_meta[set][way].live) {
        uint8_t victim_sig = line_meta[set][way].sig;
        SignatureEntry &victim_entry = sig_table[victim_sig];
        if (victim_entry.outcome > 0) victim_entry.outcome--;
    }

    // 4. Periodic decay of dead-block bits
    if (fill_count % DECAY_INTERVAL == 0) {
        for (uint32_t set = 0; set < LLC_SETS; ++set)
            for (uint32_t way = 0; way < LLC_WAYS; ++way)
                line_meta[set][way].live = false; // reset all to "dead"
    }
}

// --- Stats ---
void PrintStats() {
    std::cout << "SLDAR: SHiP-Lite Dead-Block Adaptive Replacement" << std::endl;
    // Optionally print live ratios
    uint64_t live_lines = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            live_lines += line_meta[set][way].live ? 1 : 0;
    std::cout << "Final live block ratio: "
              << 100.0 * live_lines / (LLC_SETS * LLC_WAYS) << "%" << std::endl;
}

void PrintStats_Heartbeat() {}