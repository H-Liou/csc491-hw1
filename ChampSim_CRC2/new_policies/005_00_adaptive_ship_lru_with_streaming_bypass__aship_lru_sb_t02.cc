#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- Parameters ---
#define SHIP_SIG_BITS 6
#define SHIP_TABLE_SIZE (1 << SHIP_SIG_BITS) // 64
#define SHIP_COUNTER_BITS 2
#define SHIP_TABLE_ENTRIES 2048 // 2K entries, 2 bits each
#define STREAM_DELTA_HISTORY 4
#define STREAM_DELTA_THRESHOLD 3

// --- Replacement State ---
struct LineState {
    uint8_t lru; // 0 = MRU, 15 = LRU
    uint8_t signature : SHIP_SIG_BITS;
};

std::vector<LineState> line_state; // LLC_SETS * LLC_WAYS

// SHiP-lite: 2K entries, 2 bits each
std::vector<uint8_t> ship_table; // SHIP_TABLE_ENTRIES

// Streaming detector per set
struct StreamHistory {
    int64_t deltas[STREAM_DELTA_HISTORY];
    uint8_t ptr;
    bool streaming;
};
std::vector<StreamHistory> stream_hist; // LLC_SETS
std::vector<uint64_t> last_addr; // LLC_SETS

// --- Helper Functions ---
inline uint16_t get_signature(uint64_t PC) {
    // Simple hash: lower SHIP_SIG_BITS bits of PC
    return (PC ^ (PC >> SHIP_SIG_BITS)) & (SHIP_TABLE_ENTRIES - 1);
}

inline bool is_streaming_set(uint32_t set) {
    return stream_hist[set].streaming;
}

// --- API Functions ---
void InitReplacementState() {
    line_state.resize(LLC_SETS * LLC_WAYS);
    ship_table.resize(SHIP_TABLE_ENTRIES, 1); // Start neutral
    stream_hist.resize(LLC_SETS);
    last_addr.resize(LLC_SETS, 0);

    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            line_state[set * LLC_WAYS + way].lru = way; // initialize LRU stack
            line_state[set * LLC_WAYS + way].signature = 0;
        }
        stream_hist[set].ptr = 0;
        stream_hist[set].streaming = false;
        memset(stream_hist[set].deltas, 0, sizeof(stream_hist[set].deltas));
        last_addr[set] = 0;
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
    // Streaming: bypass, don't fill cache
    if (is_streaming_set(set))
        return LLC_WAYS; // special value: don't fill

    // Pure LRU: evict line with max lru value
    uint32_t victim = 0;
    uint8_t max_lru = 0;
    for (uint32_t way = 0; way < LLC_WAYS; ++way) {
        if (line_state[set * LLC_WAYS + way].lru > max_lru) {
            max_lru = line_state[set * LLC_WAYS + way].lru;
            victim = way;
        }
    }
    return victim;
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

    // --- Streaming bypass logic ---
    if (sh.streaming) {
        // Do not fill cache (simulate bypass)
        return;
    }

    // --- SHiP-lite update ---
    if (hit) {
        // Update SHiP outcome: increment reuse counter
        if (ship_table[sig] < 3)
            ship_table[sig]++;
        // Move to MRU
        uint8_t old_lru = line_state[set * LLC_WAYS + way].lru;
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            if (line_state[set * LLC_WAYS + w].lru < old_lru)
                line_state[set * LLC_WAYS + w].lru++;
        }
        line_state[set * LLC_WAYS + way].lru = 0;
        return;
    } else {
        // On miss/eviction: decrement reuse counter
        if (ship_table[sig] > 0)
            ship_table[sig]--;
    }

    // --- On fill ---
    // Choose insertion depth based on SHiP-lite outcome
    uint8_t insert_lru = 1; // default: LRU-1
    if (ship_table[sig] >= 2)
        insert_lru = 0; // high reuse: MRU

    // Update LRU stack
    for (uint32_t w = 0; w < LLC_WAYS; ++w) {
        if (line_state[set * LLC_WAYS + w].lru < LLC_WAYS - 1)
            line_state[set * LLC_WAYS + w].lru++;
    }
    line_state[set * LLC_WAYS + way].lru = insert_lru;
    line_state[set * LLC_WAYS + way].signature = sig;
}

void PrintStats() {
    std::cout << "ASHIP-LRU-SB Policy: SHiP-lite signature-based insertion + streaming-aware bypass + pure LRU victim selection\n";
}

void PrintStats_Heartbeat() {
    // Optionally print periodic stats
}