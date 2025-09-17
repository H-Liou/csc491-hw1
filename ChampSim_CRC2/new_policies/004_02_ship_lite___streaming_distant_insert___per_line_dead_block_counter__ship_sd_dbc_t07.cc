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
#define DEAD_BITS 2
#define DEAD_MAX ((1 << DEAD_BITS) - 1)
#define SHIP_SIG_BITS 6
#define SHIP_ENTRIES 2048 // 2K entries, 2 bits each
#define STREAM_DELTA_HISTORY 4
#define STREAM_DELTA_THRESHOLD 3

// --- Replacement State ---
struct LineState {
    uint8_t rrpv : RRPV_BITS;
    uint8_t dead : DEAD_BITS;
    uint8_t signature : SHIP_SIG_BITS;
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

// --- Helper Functions ---
inline uint16_t get_signature(uint64_t PC) {
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
            line_state[set * LLC_WAYS + way].dead = 0;
            line_state[set * LLC_WAYS + way].signature = 0;
        }
        stream_hist[set].ptr = 0;
        stream_hist[set].streaming = false;
        memset(stream_hist[set].deltas, 0, sizeof(stream_hist[set].deltas));
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
    // Prefer blocks with highest dead counter, then RRPV (max)
    uint32_t victim = 0;
    uint8_t max_dead = 0;
    bool found_dead = false;

    for (uint32_t way = 0; way < LLC_WAYS; ++way) {
        uint8_t dead = line_state[set * LLC_WAYS + way].dead;
        if (dead == DEAD_MAX) {
            victim = way;
            found_dead = true;
            break;
        }
        if (dead > max_dead) {
            max_dead = dead;
            victim = way;
        }
    }
    if (found_dead) return victim;

    // If no max-dead block, select by RRPV
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (line_state[set * LLC_WAYS + way].rrpv == RRPV_MAX)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (line_state[set * LLC_WAYS + way].rrpv < RRPV_MAX)
                line_state[set * LLC_WAYS + way].rrpv++;
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
        // Reset RRPV, clear dead-block counter, update SHiP
        line_state[set * LLC_WAYS + way].rrpv = 0;
        line_state[set * LLC_WAYS + way].dead = 0;
        if (ship_table[sig] < 3)
            ship_table[sig]++;
        return;
    }

    // --- On fill ---
    uint8_t insert_rrpv = RRPV_MAX; // default: distant
    if (is_streaming_set(set)) {
        insert_rrpv = RRPV_MAX; // Streaming: always insert distant (no bypass)
    } else if (ship_table[sig] >= 2) {
        insert_rrpv = RRPV_MAX - 1; // likely reused, insert at SRRIP-1
    } // else leave at distant

    line_state[set * LLC_WAYS + way].rrpv = insert_rrpv;
    line_state[set * LLC_WAYS + way].signature = sig;
    line_state[set * LLC_WAYS + way].dead = 0; // new fill, presume live

    // --- On eviction: update SHiP and dead-block counter ---
    if (victim_addr) {
        uint16_t victim_sig = line_state[set * LLC_WAYS + way].signature;
        if (line_state[set * LLC_WAYS + way].rrpv == RRPV_MAX && ship_table[victim_sig] > 0)
            ship_table[victim_sig]--;
        // If evicted block was not reused (distant), increment dead-block counter
        if (line_state[set * LLC_WAYS + way].dead < DEAD_MAX)
            line_state[set * LLC_WAYS + way].dead++;
    }

    // --- Periodic decay of dead-block counters (every 1024 fills) ---
    static uint64_t fill_count = 0;
    fill_count++;
    if ((fill_count & 0x3FF) == 0) {
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            for (uint32_t w = 0; w < LLC_WAYS; ++w)
                if (line_state[s * LLC_WAYS + w].dead > 0)
                    line_state[s * LLC_WAYS + w].dead--;
    }
}

void PrintStats() {
    std::cout << "SHiP-SD-DBC: SHiP-lite signature insertion + streaming detector (distant insert) + per-line dead-block counter\n";
}

void PrintStats_Heartbeat() {
    // Optionally print periodic stats
}