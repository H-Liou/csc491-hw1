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
#define LEADER_SETS 32
#define PSEL_BITS 10
#define STREAM_DELTA_HISTORY 4
#define STREAM_DELTA_THRESHOLD 3
#define DECAY_PERIOD 8192 // lines

// --- Replacement State ---
struct LineState {
    uint8_t rrpv : RRPV_BITS;
    uint8_t reuse : 1; // 1 if reused since fill
};

struct StreamHistory {
    int64_t deltas[STREAM_DELTA_HISTORY];
    uint8_t ptr;
    bool streaming;
    uint64_t last_addr;
};

std::vector<LineState> line_state; // LLC_SETS * LLC_WAYS
std::vector<StreamHistory> stream_hist; // LLC_SETS
std::vector<uint8_t> is_leader_set; // LLC_SETS

uint16_t psel = 512; // 10-bit
uint64_t decay_counter = 0;

// --- Helper Functions ---
inline bool is_streaming_set(uint32_t set) {
    return stream_hist[set].streaming;
}

inline uint8_t get_leader_type(uint32_t set) {
    if (set < LEADER_SETS) return 1; // SRRIP leader
    if (set >= LLC_SETS - LEADER_SETS) return 2; // BRRIP leader
    return 0;
}

// --- API Functions ---
void InitReplacementState() {
    line_state.resize(LLC_SETS * LLC_WAYS);
    stream_hist.resize(LLC_SETS);
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
            line_state[set * LLC_WAYS + way].reuse = 0;
        }
        stream_hist[set].ptr = 0;
        stream_hist[set].streaming = false;
        stream_hist[set].last_addr = 0;
        memset(stream_hist[set].deltas, 0, sizeof(stream_hist[set].deltas));
    }
    psel = 512;
    decay_counter = 0;
}

uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Streaming: always evict block with max RRPV
    if (is_streaming_set(set)) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (line_state[set * LLC_WAYS + way].rrpv == RRPV_MAX)
                return way;
        }
        // If none at max, increment all and retry
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            line_state[set * LLC_WAYS + way].rrpv = std::min((uint8_t)(line_state[set * LLC_WAYS + way].rrpv + 1), (uint8_t)RRPV_MAX);
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (line_state[set * LLC_WAYS + way].rrpv == RRPV_MAX)
                return way;
        }
        return 0; // fallback
    }

    // Prefer dead blocks (reuse==0) at max RRPV
    for (uint32_t way = 0; way < LLC_WAYS; ++way) {
        if (line_state[set * LLC_WAYS + way].rrpv == RRPV_MAX && line_state[set * LLC_WAYS + way].reuse == 0)
            return way;
    }
    // Otherwise, block with max RRPV
    for (uint32_t way = 0; way < LLC_WAYS; ++way) {
        if (line_state[set * LLC_WAYS + way].rrpv == RRPV_MAX)
            return way;
    }
    // If none at max, increment all and retry
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        line_state[set * LLC_WAYS + way].rrpv = std::min((uint8_t)(line_state[set * LLC_WAYS + way].rrpv + 1), (uint8_t)RRPV_MAX);
    // Try again
    for (uint32_t way = 0; way < LLC_WAYS; ++way) {
        if (line_state[set * LLC_WAYS + way].rrpv == RRPV_MAX)
            return way;
    }
    return 0; // fallback
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
    StreamHistory &sh = stream_hist[set];
    int64_t delta = 0;
    if (sh.last_addr) delta = (int64_t)paddr - (int64_t)sh.last_addr;
    sh.last_addr = paddr;
    sh.deltas[sh.ptr] = delta;
    sh.ptr = (sh.ptr + 1) % STREAM_DELTA_HISTORY;
    int match = 0;
    for (uint8_t i = 1; i < STREAM_DELTA_HISTORY; ++i) {
        if (sh.deltas[i] == sh.deltas[0] && sh.deltas[0] != 0)
            match++;
    }
    sh.streaming = (match >= STREAM_DELTA_THRESHOLD);

    // --- Dead-block decay ---
    decay_counter++;
    if (decay_counter % DECAY_PERIOD == 0) {
        for (uint32_t s = 0; s < LLC_SETS; ++s) {
            for (uint32_t w = 0; w < LLC_WAYS; ++w) {
                line_state[s * LLC_WAYS + w].reuse = 0;
            }
        }
    }

    // --- On hit ---
    if (hit) {
        // Mark as reused
        line_state[set * LLC_WAYS + way].reuse = 1;
        // Promote: set RRPV to 0 (MRU)
        line_state[set * LLC_WAYS + way].rrpv = 0;
        return;
    }

    // --- On fill ---
    // Streaming: always insert at distant RRPV
    if (sh.streaming) {
        line_state[set * LLC_WAYS + way].rrpv = RRPV_MAX;
        line_state[set * LLC_WAYS + way].reuse = 0;
        return;
    }

    // Set-dueling: choose SRRIP/BRRIP insertion
    uint8_t use_srrip = 0;
    if (is_leader_set[set] == 1) use_srrip = 1;
    else if (is_leader_set[set] == 2) use_srrip = 0;
    else use_srrip = (psel >= 512);

    if (use_srrip) {
        // SRRIP: insert at RRPV=2
        line_state[set * LLC_WAYS + way].rrpv = RRPV_MAX - 1;
    } else {
        // BRRIP: insert at RRPV=2 with low probability, else at RRPV=3
        if ((rand() % 32) == 0)
            line_state[set * LLC_WAYS + way].rrpv = RRPV_MAX - 1;
        else
            line_state[set * LLC_WAYS + way].rrpv = RRPV_MAX;
    }
    line_state[set * LLC_WAYS + way].reuse = 0;

    // --- DIP set-dueling update ---
    if (is_leader_set[set] == 1 && !hit)
        psel = std::min((uint16_t)(psel + 1), (uint16_t)((1 << PSEL_BITS) - 1));
    else if (is_leader_set[set] == 2 && !hit)
        psel = (psel > 0) ? psel - 1 : 0;
}

void PrintStats() {
    std::cout << "SARRIP-DBD Policy: Streaming-aware RRIP, dead-block decay, set-dueling SRRIP/BRRIP\n";
}

void PrintStats_Heartbeat() {
    // Optionally print periodic stats
}