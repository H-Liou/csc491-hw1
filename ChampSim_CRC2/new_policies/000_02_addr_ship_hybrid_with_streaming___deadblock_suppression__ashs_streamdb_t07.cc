#include <vector>
#include <cstdint>
#include <cstring>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- Parameters ---
#define ADDR_HASH_BITS 8         // Per-line address hash
#define DEAD_BLOCK_BITS 2        // Per-line dead-block counter
#define SHIP_SIG_BITS 6          // PC signature bits
#define SHIP_SIG_ENTRIES 2048    // Global SHiP table entries
#define SHIP_SIG_OUTCOME_BITS 2  // Outcome counter bits
#define STREAM_DETECT_BITS 3     // Per-set streaming detector bits

// --- Metadata Structures ---
struct LINE_META {
    uint8_t addr_hash;                  // 8 bits
    uint8_t dead_block_ctr;             // 2 bits
    uint8_t ship_sig;                   // 6 bits
    uint8_t rrpv;                       // 2 bits
};

struct SET_META {
    uint64_t last_addr;
    int64_t last_stride;
    uint8_t stream_ctr;                 // 3 bits: streaming evidence
};

static LINE_META line_meta[LLC_SETS][LLC_WAYS];
static SET_META set_meta[LLC_SETS];

// SHiP global table: 2048 entries, 2 bits each
static uint8_t ship_outcome[SHIP_SIG_ENTRIES];

// Dead-block periodic decay counter
static uint64_t last_decay_cycle = 0;
static const uint64_t DECAY_PERIOD = 100000;

// CRC hash for PC signatures and address hashes
static inline uint16_t get_ship_sig(uint64_t PC) {
    return (champsim_crc2(PC, 0) & ((1ULL<<SHIP_SIG_BITS)-1));
}
static inline uint8_t get_addr_hash(uint64_t paddr) {
    return (champsim_crc2(paddr, 0) & ((1ULL<<ADDR_HASH_BITS)-1));
}

// --- Initialization ---
void InitReplacementState() {
    memset(line_meta, 0, sizeof(line_meta));
    memset(set_meta, 0, sizeof(set_meta));
    memset(ship_outcome, 0, sizeof(ship_outcome));
    last_decay_cycle = 0;
}

// --- Streaming Detection (per set) ---
bool is_streaming(uint32_t set, uint64_t curr_addr) {
    SET_META &sm = set_meta[set];
    int64_t stride = (int64_t)curr_addr - (int64_t)sm.last_addr;
    if (sm.last_addr != 0) {
        if (sm.last_stride == stride && stride != 0) {
            // Monotonic stride persists
            if (sm.stream_ctr < 7) sm.stream_ctr++;
        } else {
            if (sm.stream_ctr > 0) sm.stream_ctr--;
        }
    }
    sm.last_stride = stride;
    sm.last_addr = curr_addr;
    return (sm.stream_ctr >= 5);
}

// --- Find Victim ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Standard RRIP victim selection: choose line with RRPV==3, else increment all and retry
    for (int loop=0; loop<4; ++loop) {
        for (uint32_t way=0; way<LLC_WAYS; ++way) {
            if (line_meta[set][way].rrpv == 3)
                return way;
        }
        for (uint32_t way=0; way<LLC_WAYS; ++way)
            if (line_meta[set][way].rrpv < 3)
                line_meta[set][way].rrpv++;
    }
    // Fallback: evict way 0
    return 0;
}

// --- Update Replacement State ---
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
    // Decay dead-block counters and SHiP outcomes every DECAY_PERIOD cycles (approx)
    static uint64_t global_access = 0;
    global_access++;
    if (global_access - last_decay_cycle >= DECAY_PERIOD) {
        // Decay all lines' dead-block counters
        for (uint32_t s=0; s<LLC_SETS; ++s)
            for (uint32_t w=0; w<LLC_WAYS; ++w)
                if (line_meta[s][w].dead_block_ctr > 0)
                    line_meta[s][w].dead_block_ctr--;
        // Decay SHiP global table
        for (uint32_t i=0; i<SHIP_SIG_ENTRIES; ++i)
            if (ship_outcome[i] > 0) ship_outcome[i]--;
        last_decay_cycle = global_access;
    }

    LINE_META &lm = line_meta[set][way];
    uint16_t sig_idx = get_ship_sig(PC);
    uint8_t addr_hash = get_addr_hash(paddr);

    // On hit: reward SHiP, reset dead-block counter, promote to MRU
    if (hit) {
        if (ship_outcome[sig_idx] < 3) ship_outcome[sig_idx]++;
        lm.dead_block_ctr = 0;
        lm.rrpv = 0;
    }
    else {
        // On miss/eviction: penalize SHiP, increment dead-block counter
        if (ship_outcome[sig_idx] > 0) ship_outcome[sig_idx]--;
        if (lm.dead_block_ctr < 3) lm.dead_block_ctr++;
    }

    // Insertion policy
    bool streaming = is_streaming(set, paddr);

    // Address hash reuse check: scan ways for matching hash
    bool addr_hot = false;
    for (uint32_t w=0; w<LLC_WAYS; ++w) {
        if (w == way) continue;
        if (line_meta[set][w].addr_hash == addr_hash) {
            addr_hot = true;
            break;
        }
    }
    bool ship_hot = (ship_outcome[sig_idx] >= 2);
    bool dead_block = (lm.dead_block_ctr >= 2);

    // Compose insertion decisions
    if (streaming) {
        // Streaming: bypass cold blocks, insert LRU if not hot
        if (addr_hot || ship_hot)
            lm.rrpv = 0; // protect reusable lines
        else
            lm.rrpv = 3; // insert LRU (bypass)
    }
    else if (dead_block) {
        lm.rrpv = 3; // likely dead, insert LRU
    }
    else if (addr_hot || ship_hot) {
        lm.rrpv = 0; // hot: insert MRU (protect)
    }
    else {
        lm.rrpv = 2; // neutral: mid-distance
    }

    lm.addr_hash = addr_hash;
    lm.ship_sig = sig_idx;
    // dead_block_ctr updated above

    // [Optional] If victim_addr != 0 (eviction), update SHiP for evicted block
    // Not strictly necessary, handled above
}

// --- Statistics ---
void PrintStats() {
    // (Optional) Print summary statistics
    std::cout << "ASHS-StreamDB: End of simulation\n";
}
void PrintStats_Heartbeat() {
    // (Optional) Print periodic stats
}