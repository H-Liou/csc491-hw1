#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- Metadata structures ---
// 2-bit RRPV per block
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// SHiP-lite: 6-bit signature table, 2-bit outcome counters
#define SHIP_SIG_BITS 6
#define SHIP_TABLE_SIZE 1024
struct SHIPEntry {
    uint8_t counter; // 2 bits
};
SHIPEntry ship_table[SHIP_TABLE_SIZE];

// Per-block: store signature and dead-block counter
struct BlockMeta {
    uint8_t signature; // 6 bits
    uint8_t dead_ctr;  // 2 bits
};
BlockMeta block_meta[LLC_SETS][LLC_WAYS];

// Streaming detector: per-set last address, delta, streaming flag
struct StreamDetect {
    uint64_t last_addr;
    int64_t last_delta;
    uint8_t stream_count; // 2 bits
    bool is_streaming;
};
StreamDetect stream_detect[LLC_SETS];

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv)); // 2-bit RRPV, init to max
    memset(ship_table, 0, sizeof(ship_table));
    memset(block_meta, 0, sizeof(block_meta));
    memset(stream_detect, 0, sizeof(stream_detect));
}

// --- SHiP-lite signature extraction ---
inline uint8_t GetSignature(uint64_t PC) {
    // Simple hash: lower SHIP_SIG_BITS bits of CRC32(PC)
    return champsim_crc2(PC) & ((1 << SHIP_SIG_BITS) - 1);
}

// --- Streaming detector ---
// Returns true if streaming detected for this set
bool DetectStreaming(uint32_t set, uint64_t paddr) {
    StreamDetect &sd = stream_detect[set];
    int64_t delta = paddr - sd.last_addr;
    if (sd.last_addr != 0) {
        if (delta == sd.last_delta && delta != 0) {
            if (sd.stream_count < 3) ++sd.stream_count;
        } else {
            if (sd.stream_count > 0) --sd.stream_count;
        }
        sd.is_streaming = (sd.stream_count >= 2);
    }
    sd.last_delta = delta;
    sd.last_addr = paddr;
    return sd.is_streaming;
}

// --- Dead-block counter decay (periodic) ---
void DecayDeadBlockCounters() {
    static uint64_t decay_tick = 0;
    decay_tick++;
    if (decay_tick % 100000 == 0) {
        for (uint32_t set = 0; set < LLC_SETS; ++set)
            for (uint32_t way = 0; way < LLC_WAYS; ++way)
                if (block_meta[set][way].dead_ctr > 0)
                    block_meta[set][way].dead_ctr--;
    }
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
    // Standard SRRIP victim selection
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (rrpv[set][way] == 3)
                return way;
        }
        // Increment all RRPVs
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] < 3) ++rrpv[set][way];
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
    // --- Streaming detector ---
    bool streaming = DetectStreaming(set, paddr);

    // --- SHiP-lite signature ---
    uint8_t sig = GetSignature(PC);
    uint32_t ship_idx = sig;

    // --- Dead-block decay (periodic) ---
    DecayDeadBlockCounters();

    // --- On hit ---
    if (hit) {
        rrpv[set][way] = 0; // MRU
        // Update SHiP outcome counter (increase reuse confidence)
        if (ship_table[ship_idx].counter < 3)
            ship_table[ship_idx].counter++;
        // Reset dead-block counter for this block
        block_meta[set][way].dead_ctr = 0;
        return;
    }

    // --- On fill ---
    // Streaming phase: bypass fill (do not insert into cache)
    if (streaming) {
        rrpv[set][way] = 3; // Insert at distant RRPV (effectively bypass)
        block_meta[set][way].signature = sig;
        block_meta[set][way].dead_ctr = 0;
        return;
    }

    // Dead-block history: if block was dead-on-arrival recently, bias toward distant RRPV
    bool likely_dead = (block_meta[set][way].dead_ctr >= 2);

    // SHiP-lite: if signature counter high, insert at MRU; else distant RRPV
    bool ship_predict_reuse = (ship_table[ship_idx].counter >= 2);

    if (ship_predict_reuse && !likely_dead) {
        rrpv[set][way] = 0; // MRU
    } else {
        rrpv[set][way] = 3; // distant RRPV
    }

    // Store signature and reset dead-block counter
    block_meta[set][way].signature = sig;
    block_meta[set][way].dead_ctr = 0;

    // --- On eviction: update SHiP and dead-block counter ---
    // Find victim block's way (if victim_addr != 0)
    if (victim_addr != 0) {
        for (uint32_t vway = 0; vway < LLC_WAYS; ++vway) {
            // Assume BLOCK has .address field (if not, skip this logic)
            // If current_set[vway].address == victim_addr
            // For simplicity, increment dead_ctr for the evicted way
            if (vway == way) {
                // If block was not reused (RRPV==3), decrease SHiP counter
                if (rrpv[set][vway] == 3 && ship_table[block_meta[set][vway].signature].counter > 0)
                    ship_table[block_meta[set][vway].signature].counter--;
                // Increment dead-block counter
                if (block_meta[set][vway].dead_ctr < 3)
                    block_meta[set][vway].dead_ctr++;
            }
        }
    }
}

// --- Print statistics ---
void PrintStats() {
    std::cout << "SLSD Policy: SHiP-lite PC Reuse + Streaming Detector + Dead-block Counters\n";
}
void PrintStats_Heartbeat() {}