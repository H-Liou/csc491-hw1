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
#define DEAD_BLOCK_BITS 2
#define DEAD_BLOCK_MAX ((1 << DEAD_BLOCK_BITS) - 1)
#define STREAM_DELTA_HISTORY 4
#define STREAM_DELTA_THRESHOLD 3
#define PSEL_BITS 10
#define LEADER_SETS 32
#define DECAY_INTERVAL 256 // Decay dead-block counters every N fills

// --- Replacement State ---
struct LineState {
    uint8_t rrpv : RRPV_BITS;
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

// DIP/DRRIP set-dueling
std::vector<uint8_t> is_leader_set; // LLC_SETS
uint16_t psel = 512; // 10-bit PSEL, midpoint

uint64_t global_fill_count = 0;

// --- Helper Functions ---
inline bool is_streaming_set(uint32_t set) {
    return stream_hist[set].streaming;
}

// --- API Functions ---
void InitReplacementState() {
    line_state.resize(LLC_SETS * LLC_WAYS);
    stream_hist.resize(LLC_SETS);
    last_addr.resize(LLC_SETS, 0);
    is_leader_set.resize(LLC_SETS, 0);

    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        if (set < LEADER_SETS)
            is_leader_set[set] = 1; // SRRIP leader
        else if (set >= LLC_SETS - LEADER_SETS)
            is_leader_set[set] = 2; // BRRIP leader
        else
            is_leader_set[set] = 0; // follower
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            line_state[set * LLC_WAYS + way].rrpv = RRPV_MAX;
            line_state[set * LLC_WAYS + way].dead = 0;
        }
        stream_hist[set].ptr = 0;
        stream_hist[set].streaming = false;
        memset(stream_hist[set].deltas, 0, sizeof(stream_hist[set].deltas));
    }
    psel = 512;
    global_fill_count = 0;
}

uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Streaming: prefer evicting dead blocks
    if (is_streaming_set(set)) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (line_state[set * LLC_WAYS + way].dead == DEAD_BLOCK_MAX)
                return way;
        }
        // If none, fall back to RRPV
    }

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

    // --- Dead-block counter update ---
    if (hit) {
        // Reset RRPV to 0 (MRU)
        line_state[set * LLC_WAYS + way].rrpv = 0;
        // Reset dead-block counter
        line_state[set * LLC_WAYS + way].dead = 0;
        return;
    } else {
        // Increment dead-block counter (up to max)
        if (line_state[set * LLC_WAYS + way].dead < DEAD_BLOCK_MAX)
            line_state[set * LLC_WAYS + way].dead++;
    }

    // --- Periodic decay of dead-block counters ---
    global_fill_count++;
    if ((global_fill_count % DECAY_INTERVAL) == 0) {
        for (uint32_t s = 0; s < LLC_SETS; ++s) {
            for (uint32_t w = 0; w < LLC_WAYS; ++w) {
                if (line_state[s * LLC_WAYS + w].dead > 0)
                    line_state[s * LLC_WAYS + w].dead--;
            }
        }
    }

    // --- Streaming: dead-block filter bypass logic ---
    if (sh.streaming && line_state[set * LLC_WAYS + way].dead == DEAD_BLOCK_MAX) {
        // Do not fill cache (simulate bypass)
        return;
    }

    // --- On fill: DRRIP insertion ---
    uint8_t insert_rrpv = RRPV_MAX; // default: distant

    // DRRIP: SRRIP (insert at RRPV=2), BRRIP (insert at RRPV=3 1/32 of time, else 2)
    if (is_leader_set[set] == 1) {
        insert_rrpv = RRPV_MAX - 1; // SRRIP: insert at 2
    } else if (is_leader_set[set] == 2) {
        insert_rrpv = (rand() % 32 == 0) ? RRPV_MAX : (RRPV_MAX - 1); // BRRIP
    } else if (psel < (1 << (PSEL_BITS - 1))) {
        insert_rrpv = RRPV_MAX - 1; // follower: SRRIP
    } else {
        insert_rrpv = (rand() % 32 == 0) ? RRPV_MAX : (RRPV_MAX - 1); // follower: BRRIP
    }

    line_state[set * LLC_WAYS + way].rrpv = insert_rrpv;
    line_state[set * LLC_WAYS + way].dead = 0;

    // --- DIP/DRRIP set-dueling update ---
    if (is_leader_set[set] == 1 && !hit)
        psel = std::min((uint16_t)(psel + 1), (uint16_t)((1 << PSEL_BITS) - 1));
    else if (is_leader_set[set] == 2 && !hit)
        psel = (psel > 0) ? psel - 1 : 0;
}

void PrintStats() {
    std::cout << "ADRRIP-SDB Policy: DRRIP set-dueling (SRRIP/BRRIP) + streaming-aware bypass + per-line dead-block counter with periodic decay\n";
}

void PrintStats_Heartbeat() {
    // Optionally print periodic stats
}