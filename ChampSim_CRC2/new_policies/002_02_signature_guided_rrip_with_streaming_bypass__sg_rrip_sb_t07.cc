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
#define RRPV_MAX ((1 << RRPV_BITS) - 1) // 3
#define SHIP_SIG_BITS 6 // 6 bits: 64 entries per set
#define SHIP_SIG_ENTRIES (1 << SHIP_SIG_BITS)
#define SHIP_SIG_MASK (SHIP_SIG_ENTRIES-1)
#define SHIP_COUNTER_BITS 2
#define STREAM_DELTA_HISTORY 4
#define STREAM_DELTA_THRESHOLD 3

// --- Replacement State ---
struct LineState {
    uint8_t rrpv : RRPV_BITS;
};

struct SHIPEntry {
    uint8_t counter : SHIP_COUNTER_BITS;
};

struct StreamHistory {
    int64_t deltas[STREAM_DELTA_HISTORY];
    uint8_t ptr;
    bool streaming;
};

std::vector<LineState> line_state; // LLC_SETS * LLC_WAYS
std::vector<SHIPEntry> ship_table; // LLC_SETS * SHIP_SIG_ENTRIES
std::vector<StreamHistory> stream_hist; // LLC_SETS
std::vector<uint64_t> last_addr; // LLC_SETS

// --- Helper Functions ---
inline uint32_t get_ship_sig(uint64_t PC) {
    return (PC >> 2) & SHIP_SIG_MASK;
}

inline bool is_streaming_set(uint32_t set) {
    return stream_hist[set].streaming;
}

// --- API Functions ---
void InitReplacementState() {
    line_state.resize(LLC_SETS * LLC_WAYS);
    ship_table.resize(LLC_SETS * SHIP_SIG_ENTRIES);
    stream_hist.resize(LLC_SETS);
    last_addr.resize(LLC_SETS, 0);

    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            line_state[set * LLC_WAYS + way].rrpv = RRPV_MAX; // old blocks: ready for eviction
        }
        for (uint32_t i = 0; i < SHIP_SIG_ENTRIES; ++i)
            ship_table[set * SHIP_SIG_ENTRIES + i].counter = 1; // neutral initial reuse
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
    if (is_streaming_set(set))
        return LLC_WAYS; // bypass: no fill

    // Find victim with RRPV == MAX
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (line_state[set * LLC_WAYS + way].rrpv == RRPV_MAX)
                return way;
        }
        // Increment all RRPVs (aging)
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (line_state[set * LLC_WAYS + way].rrpv < RRPV_MAX)
                line_state[set * LLC_WAYS + way].rrpv++;
        }
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
    for (uint8_t i = 1; i < STREAM_DELTA_HISTORY; ++i)
        if (sh.deltas[i] == sh.deltas[0] && sh.deltas[0] != 0)
            match++;
    sh.streaming = (match >= STREAM_DELTA_THRESHOLD);

    // --- SHiP signature ---
    uint32_t sig = get_ship_sig(PC);
    SHIPEntry &ship = ship_table[set * SHIP_SIG_ENTRIES + sig];

    // --- On hit: promote line ---
    if (hit) {
        line_state[set * LLC_WAYS + way].rrpv = 0; // MRU
        ship.counter = std::min((uint8_t)(ship.counter + 1), (uint8_t)((1 << SHIP_COUNTER_BITS) - 1));
        return;
    }

    // --- On fill: Streaming sets bypass ---
    if (sh.streaming)
        return; // do not insert in cache

    // --- On fill: Insert with signature-guided RRPV ---
    uint8_t insert_rrpv;
    if (ship.counter >= ((1 << SHIP_COUNTER_BITS) - 1)) {
        // Strong reuse: insert at RRPV=0 (MRU)
        insert_rrpv = 0;
    } else if (ship.counter == 2) {
        // Moderate reuse: RRPV=1 (medium)
        insert_rrpv = 1;
    } else {
        // Weak/no reuse: insert at RRPV=RRPV_MAX (aged)
        insert_rrpv = RRPV_MAX;
    }
    line_state[set * LLC_WAYS + way].rrpv = insert_rrpv;

    // --- On eviction: update SHiP ---
    if (victim_addr) {
        uint32_t victim_sig = get_ship_sig(PC);
        SHIPEntry &victim_ship = ship_table[set * SHIP_SIG_ENTRIES + victim_sig];
        if (!hit && victim_ship.counter)
            victim_ship.counter--;
    }
}

void PrintStats() {
    std::cout << "SG-RRIP-SB Policy: SHiP signature-guided RRIP insertion + streaming set bypass\n";
}

void PrintStats_Heartbeat() {
    // Optionally print periodic stats
}