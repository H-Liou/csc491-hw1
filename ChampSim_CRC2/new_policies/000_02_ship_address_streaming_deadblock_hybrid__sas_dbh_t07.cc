#include <vector>
#include <cstdint>
#include <iostream>
#include <algorithm>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- Parameters ---
#define SHIP_SIG_BITS 8 // 4 bits PC ^ 4 bits address
#define SHIP_ENTRIES 4096
#define SHIP_COUNTER_BITS 2

#define STREAM_DELTA_HISTORY 4
#define STREAM_DELTA_THRESHOLD 3
#define STREAM_BYPASS_PERIOD 2048 // decay interval

#define DEAD_BLOCK_BITS 2
#define DEAD_BLOCK_MAX ((1u << DEAD_BLOCK_BITS)-1)
#define DEAD_BLOCK_DECAY_PERIOD 2048

#define RRPV_BITS 2
#define RRPV_MAX ((1u << RRPV_BITS)-1)

// --- Structures ---
struct SHIPEntry {
    uint8_t counter; // 2 bits
};

struct BlockMeta {
    uint8_t rrpv; // 2 bits
    uint8_t dead_block; // 2 bits
    uint8_t ship_sig;   // 8 bits
};

struct StreamDetectSet {
    uint64_t last_addr;
    int64_t  deltas[STREAM_DELTA_HISTORY];
    uint8_t  idx;
    bool     streaming;
    uint64_t decay_counter;
};

std::vector<SHIPEntry> ship_table(SHIP_ENTRIES);
std::vector<BlockMeta> block_meta(LLC_SETS * LLC_WAYS);
std::vector<StreamDetectSet> stream_sets(LLC_SETS);

void InitReplacementState() {
    std::fill(ship_table.begin(), ship_table.end(), SHIPEntry{0});
    std::fill(block_meta.begin(), block_meta.end(), BlockMeta{RRPV_MAX, 0, 0});
    for(uint32_t set=0; set<LLC_SETS; ++set) {
        stream_sets[set].last_addr = 0;
        std::fill(stream_sets[set].deltas, stream_sets[set].deltas+STREAM_DELTA_HISTORY, 0);
        stream_sets[set].idx = 0;
        stream_sets[set].streaming = false;
        stream_sets[set].decay_counter = 0;
    }
}

// --- Helper: Compute SHiP signature ---
inline uint8_t GetSHIPSig(uint64_t PC, uint64_t paddr) {
    return ((PC & 0xF) ^ ((paddr >> 6) & 0xF));
}

// --- Streaming detector, per set ---
void UpdateStreamDetector(uint32_t set, uint64_t paddr) {
    StreamDetectSet &sd = stream_sets[set];
    uint64_t addr_blk = paddr >> 6;
    int64_t delta = sd.idx ? (addr_blk - sd.last_addr) : 0;
    sd.deltas[sd.idx % STREAM_DELTA_HISTORY] = delta;
    sd.idx = (sd.idx + 1) % STREAM_DELTA_HISTORY;
    sd.last_addr = addr_blk;

    // Check for monotonic stride (all deltas nonzero and same sign)
    int8_t sign = 0;
    int cnt = 0;
    for(int i=0; i<STREAM_DELTA_HISTORY; ++i) {
        if(sd.deltas[i]) {
            if(sign == 0)
                sign = (sd.deltas[i] > 0) ? 1 : -1;
            else if((sd.deltas[i] > 0 ? 1 : -1) != sign)
                sign = 0;
            ++cnt;
        }
    }
    sd.streaming = (cnt >= STREAM_DELTA_THRESHOLD && sign != 0);
    // Periodic decay to avoid stale streaming flag
    if(++sd.decay_counter > STREAM_BYPASS_PERIOD) {
        sd.streaming = false;
        sd.decay_counter = 0;
    }
}

// --- Dead-block decay globally ---
uint64_t db_decay_ctr = 0;
void DeadBlockDecay() {
    if(++db_decay_ctr % DEAD_BLOCK_DECAY_PERIOD == 0) {
        for(auto &bm : block_meta)
            if(bm.dead_block) bm.dead_block--;
    }
}

// Find victim in the set
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    DeadBlockDecay();
    // Streaming: bypass if detector triggers
    if(stream_sets[set].streaming) return LLC_WAYS; // signal bypass (caller drops fill)

    // Prefer blocks with high dead-block counter
    uint32_t victim = LLC_WAYS;
    for(uint32_t way=0; way<LLC_WAYS; ++way) {
        BlockMeta &bm = block_meta[set*LLC_WAYS+way];
        if(bm.rrpv == RRPV_MAX) {
            if(victim == LLC_WAYS || bm.dead_block > block_meta[set*LLC_WAYS+victim].dead_block)
                victim = way;
        }
    }
    // If none found, increment rrpv and repeat
    if(victim == LLC_WAYS) {
        for(uint32_t way=0; way<LLC_WAYS; ++way)
            block_meta[set*LLC_WAYS+way].rrpv = std::min(RRPV_MAX, block_meta[set*LLC_WAYS+way].rrpv+1);
        for(uint32_t way=0; way<LLC_WAYS; ++way) {
            BlockMeta &bm = block_meta[set*LLC_WAYS+way];
            if(bm.rrpv == RRPV_MAX) {
                if(victim == LLC_WAYS || bm.dead_block > block_meta[set*LLC_WAYS+victim].dead_block)
                    victim = way;
            }
        }
    }
    // If still none, pick way 0
    return (victim == LLC_WAYS) ? 0 : victim;
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
    UpdateStreamDetector(set, paddr);

    BlockMeta &bm = block_meta[set*LLC_WAYS+way];
    uint8_t sig = GetSHIPSig(PC, paddr);

    // If streaming detected, don't update SHiP or dead-block
    if(stream_sets[set].streaming) return;

    // SHiP update: On hit, increment, else decrement signature counter
    uint32_t ship_idx = sig;
    if(hit) {
        if(ship_table[ship_idx].counter < ((1u << SHIP_COUNTER_BITS)-1))
            ship_table[ship_idx].counter++;
        // Dead-block: mark as reused
        bm.dead_block = 0;
    } else {
        if(ship_table[ship_idx].counter)
            ship_table[ship_idx].counter--;
        // Dead-block: increment on miss/eviction if not reused
        if(bm.dead_block < DEAD_BLOCK_MAX)
            bm.dead_block++;
    }

    // On fill/replace, set RRPV based on blended logic
    // If streaming: insert at distant RRPV (do nothing here, skip fill)
    // If SHiP strong reuse, insert at MRU (RRPV=0)
    // If dead-block high, insert at distant RRPV (RRPV=RRPV_MAX)
    // Else, default insertion (SRRIP, RRPV=2)
    bm.ship_sig = sig;
    if(ship_table[ship_idx].counter >= 2)
        bm.rrpv = 0;
    else if(bm.dead_block >= DEAD_BLOCK_MAX)
        bm.rrpv = RRPV_MAX;
    else
        bm.rrpv = RRPV_MAX-1;
}

// Print end-of-simulation statistics
void PrintStats() {
    uint64_t ship_hits = 0, ship_fills = 0;
    for(auto &entry : ship_table)
        ship_hits += entry.counter;
    std::cout << "SAS-DBH SHiP counters sum: " << ship_hits << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Optional: Print streaming sets active
    uint32_t streaming_cnt = 0;
    for(auto &sd : stream_sets)
        if(sd.streaming) streaming_cnt++;
    std::cout << "SAS-DBH streaming sets active: " << streaming_cnt << std::endl;
}