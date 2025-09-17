#include <vector>
#include <cstdint>
#include <cstring>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- Parameters ---
#define RRPV_BITS 2
#define RRPV_MAX ((1 << RRPV_BITS) - 1)
#define SHIP_SIG_BITS 6
#define SHIP_TABLE_SIZE (1 << SHIP_SIG_BITS) // 64
#define SHIP_ENTRIES 2048 // 2K entries, 2 bits each
#define STREAM_DELTA_HISTORY 4
#define STREAM_DELTA_THRESHOLD 3
#define DEAD_BLOCK_BITS 1
#define DEAD_DECAY_INTERVAL 4096 // Decay every 4K fills

// --- Replacement State ---
struct LineState {
    uint8_t rrpv : RRPV_BITS;
    uint8_t signature : SHIP_SIG_BITS;
    uint8_t dead : DEAD_BLOCK_BITS;
};

struct StreamHistory {
    int64_t deltas[STREAM_DELTA_HISTORY];
    uint8_t ptr;
    bool streaming;
};

std::vector<LineState> line_state; // LLC_SETS * LLC_WAYS
std::vector<StreamHistory> stream_hist; // LLC_SETS
std::vector<uint64_t> last_addr; // LLC_SETS

// SHiP-lite: 2K entries, 2 bits each
std::vector<uint8_t> ship_table; // SHIP_ENTRIES

uint64_t fill_count = 0; // For dead-block decay

// --- Helper Functions ---
inline uint16_t get_signature(uint64_t PC) {
    // Simple hash: lower SHIP_SIG_BITS bits of PC
    return (PC ^ (PC >> SHIP_SIG_BITS)) & (SHIP_ENTRIES - 1);
}

inline bool is_streaming_set(uint32_t set) {
    return stream_hist[set].streaming;
}

// --- API Functions ---
void InitReplacementState() {
    line_state.resize(LLC_SETS * LLC_WAYS);
    stream_hist.resize(LLC_SETS);
    last_addr.resize(LLC_SETS, 0);
    ship_table.resize(SHIP_ENTRIES, 1); // Start neutral

    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            line_state[set * LLC_WAYS + way].rrpv = RRPV_MAX;
            line_state[set * LLC_WAYS + way].signature = 0;
            line_state[set * LLC_WAYS + way].dead = 0;
        }
        stream_hist[set].ptr = 0;
        stream_hist[set].streaming = false;
        memset(stream_hist[set].deltas, 0, sizeof(stream_hist[set].deltas));
    }
    fill_count = 0;
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
    // Standard RRIP victim selection
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (line_state[set * LLC_WAYS + way].rrpv == RRPV_MAX)
                return way;
        }
        // Increment all RRPVs
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (line_state[set * LLC_WAYS + way].rrpv < RRPV_MAX)
                line_state[set * LLC_WAYS + way].rrpv++;
    }
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
    // --- Streaming Detector ---
    int64_t delta = 0;
    if (last_addr[set]) delta = (int64_t)paddr - (int64_t)last_addr[set];
    last_addr[set] = paddr;
    StreamHistory &sh = stream_hist[set];
    sh.deltas[sh.ptr] = delta;
    sh.ptr = (sh.ptr + 1) % STREAM_DELTA_HISTORY;
    int match = 0;
    for (uint8_t i = 1; i < STREAM_DELTA_HISTORY; ++i) {
        if (sh.deltas[i] == sh.deltas[0] && sh.deltas[0] != 0)
            match++;
    }
    sh.streaming = (match >= STREAM_DELTA_THRESHOLD);

    // --- SHiP-lite signature ---
    uint16_t sig = get_signature(PC);

    // --- On hit ---
    if (hit) {
        // Reset RRPV to 0 (MRU)
        line_state[set * LLC_WAYS + way].rrpv = 0;
        // Update SHiP outcome: increment reuse counter
        if (ship_table[sig] < 3)
            ship_table[sig]++;
        // Clear dead-block bit
        line_state[set * LLC_WAYS + way].dead = 0;
        return;
    }

    // --- On fill ---
    fill_count++;
    uint8_t insert_rrpv = RRPV_MAX; // default: distant

    // Use SHiP-lite outcome to bias insertion
    if (ship_table[sig] >= 2)
        insert_rrpv = RRPV_MAX - 1; // likely reused, insert at SRRIP-1
    else
        insert_rrpv = RRPV_MAX; // likely dead, insert at SRRIP-max

    // If streaming detected, always insert at RRPV_MAX (distant)
    if (sh.streaming)
        insert_rrpv = RRPV_MAX;

    // If dead-block bit set, force distant insertion
    if (line_state[set * LLC_WAYS + way].dead)
        insert_rrpv = RRPV_MAX;

    line_state[set * LLC_WAYS + way].rrpv = insert_rrpv;
    line_state[set * LLC_WAYS + way].signature = sig;
    line_state[set * LLC_WAYS + way].dead = 0; // reset on fill

    // --- On eviction: update SHiP outcome and dead-block ---
    if (victim_addr) {
        uint16_t victim_sig = line_state[set * LLC_WAYS + way].signature;
        // If evicted block was not reused (RRPV==max), decrement reuse counter
        if (line_state[set * LLC_WAYS + way].rrpv == RRPV_MAX && ship_table[victim_sig] > 0)
            ship_table[victim_sig]--;
        // If evicted block was not reused, set dead-block bit
        if (line_state[set * LLC_WAYS + way].rrpv == RRPV_MAX)
            line_state[set * LLC_WAYS + way].dead = 1;
    }

    // --- Dead-block decay: periodically clear dead bits ---
    if ((fill_count % DEAD_DECAY_INTERVAL) == 0) {
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            for (uint32_t w = 0; w < LLC_WAYS; ++w)
                line_state[s * LLC_WAYS + w].dead = 0;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "SHiP-DBC-ASI Policy: SHiP-lite signature insertion + dead-block counter + adaptive streaming insertion\n";
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Optionally print periodic stats
}