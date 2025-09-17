#include <vector>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// RRIP parameters
#define RRPV_BITS 2
#define RRPV_MAX ((1<<RRPV_BITS)-1)
#define SRRIP_INSERT 0
#define BRRIP_INSERT (RRPV_MAX-1)

// SHiP-lite parameters
#define SHIP_SIG_BITS 6
#define SHIP_TABLE_SIZE (1<<SHIP_SIG_BITS) // 64
#define SHIP_ENTRIES (LLC_SETS)            // 2048
#define SHIP_COUNTER_BITS 2
#define SHIP_MAX ((1<<SHIP_COUNTER_BITS)-1)
#define SHIP_THRESHOLD 1

// Streaming delta detector per set
#define DELTA_STREAM_COUNT_BITS 2
#define DELTA_STREAM_THRESHOLD 3 // Flag streaming phase after 3 consecutive deltas

struct block_state_t {
    uint8_t rrpv;
    uint8_t ship_sig;
    bool valid;
};
std::vector<std::vector<block_state_t>> blocks(LLC_SETS, std::vector<block_state_t>(LLC_WAYS));

// SHiP-lite table: per-signature outcome counter
struct ship_entry_t {
    uint8_t counter; // 2 bits
};
std::vector<ship_entry_t> ship_table(SHIP_TABLE_SIZE * SHIP_ENTRIES);

// Streaming delta detector: per set
struct delta_stream_t {
    uint64_t last_addr;
    uint64_t prev_addr;
    uint8_t stream_count; // 2 bits
    bool in_stream; // phase flag
};
std::vector<delta_stream_t> delta_detector(LLC_SETS);

// --- Helper: get PC signature ---
inline uint8_t get_ship_sig(uint64_t PC, uint32_t set) {
    return ((PC >> 2) ^ set) & (SHIP_TABLE_SIZE-1);
}

// --- Helper: get SHiP table index ---
inline uint32_t get_ship_idx(uint32_t set, uint8_t sig) {
    return (set * SHIP_TABLE_SIZE) + sig;
}

// --- Init ---
void InitReplacementState() {
    for (uint32_t s = 0; s < LLC_SETS; s++) {
        for (uint32_t w = 0; w < LLC_WAYS; w++)
            blocks[s][w] = {RRPV_MAX, 0, false};
        delta_detector[s].last_addr = 0;
        delta_detector[s].prev_addr = 0;
        delta_detector[s].stream_count = 0;
        delta_detector[s].in_stream = false;
    }
    for (auto &entry : ship_table)
        entry.counter = SHIP_THRESHOLD;
}

// --- Victim selection (RRIP) ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    while(true) {
        for (uint32_t w = 0; w < LLC_WAYS; w++) {
            if (blocks[set][w].rrpv == RRPV_MAX)
                return w;
        }
        for (uint32_t w = 0; w < LLC_WAYS; w++) {
            if (blocks[set][w].rrpv < RRPV_MAX)
                blocks[set][w].rrpv++;
        }
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
    // Streaming delta detection (block addr granularity)
    delta_stream_t &ds = delta_detector[set];
    uint64_t curr_addr = paddr >> 6; // 64B block

    // Only update on fill (miss)
    if (!hit) {
        uint64_t delta1 = curr_addr - ds.last_addr;
        uint64_t delta2 = ds.last_addr - ds.prev_addr;

        // Detect near-monotonic streaming: delta == delta2, and small stride
        if (ds.prev_addr != 0 && delta1 == delta2 && (delta1 == 1 || delta1 == -1 || delta1 < 8)) {
            if (ds.stream_count < ((1<<DELTA_STREAM_COUNT_BITS)-1))
                ds.stream_count++;
        } else {
            ds.stream_count = 0;
        }
        ds.in_stream = (ds.stream_count >= DELTA_STREAM_THRESHOLD);
        ds.prev_addr = ds.last_addr;
        ds.last_addr = curr_addr;
    }

    // Get PC signature
    uint8_t sig = get_ship_sig(PC, set);
    uint32_t ship_idx = get_ship_idx(set, sig);

    // On hit: set block to MRU, increment SHiP counter
    if (hit) {
        blocks[set][way].rrpv = SRRIP_INSERT;
        blocks[set][way].ship_sig = sig;
        blocks[set][way].valid = true;
        if (ship_table[ship_idx].counter < SHIP_MAX)
            ship_table[ship_idx].counter++;
        return;
    }

    // On miss: update SHiP counter for victim block
    if (blocks[set][way].valid) {
        uint8_t victim_sig = blocks[set][way].ship_sig;
        uint32_t victim_idx = get_ship_idx(set, victim_sig);
        if (ship_table[victim_idx].counter > 0)
            ship_table[victim_idx].counter--;
    }

    // Decide insertion depth
    uint8_t ins_rrpv;
    if (ds.in_stream) {
        ins_rrpv = BRRIP_INSERT; // streaming phase: insert at distant RRPV
    } else {
        bool ship_predicts_reuse = (ship_table[ship_idx].counter >= SHIP_THRESHOLD);
        ins_rrpv = ship_predicts_reuse ? SRRIP_INSERT : BRRIP_INSERT;
    }
    blocks[set][way].rrpv = ins_rrpv;
    blocks[set][way].ship_sig = sig;
    blocks[set][way].valid = true;
}

// --- Print stats ---
void PrintStats() {
    uint32_t streaming_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; s++)
        if (delta_detector[s].in_stream)
            streaming_sets++;
    std::cout << "SL-SD: Streaming sets=" << streaming_sets << "/" << LLC_SETS << std::endl;
}

// --- Print heartbeat stats ---
void PrintStats_Heartbeat() {
    // No periodic stats needed
}