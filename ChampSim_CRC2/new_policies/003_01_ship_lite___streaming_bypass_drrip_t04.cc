#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// DRRIP parameters
#define RRPV_MAX 3
#define PSEL_MAX 1023
#define NUM_LEADER_SETS 32

// SHiP-lite parameters
#define SHIP_SIG_BITS 6
#define SHIP_SIG_ENTRIES (1 << SHIP_SIG_BITS)
#define SHIP_CTR_MAX 3

// Streaming detector parameters
#define STREAM_WIN_SIZE 8
#define STREAM_DELTA_THRESHOLD 6

// Replacement state
struct LINE_META {
    uint8_t rrpv;            // 2 bits per line
    uint8_t ship_sig;        // 6 bits per line
};

static LINE_META repl_meta[LLC_SETS][LLC_WAYS];

// SHiP signature outcome table
static uint8_t ship_ctr[SHIP_SIG_ENTRIES];

// DRRIP set-dueling
static uint16_t psel = PSEL_MAX / 2;
static bool is_leader_set[LLC_SETS];
static bool leader_is_srrip[LLC_SETS];

// Streaming detector per set
struct StreamDetect {
    uint64_t last_addr;
    int deltas[STREAM_WIN_SIZE];
    int idx;
    int stream_score;
};
static StreamDetect stream_meta[LLC_SETS];

// Utility: get SHiP signature from PC
inline uint8_t get_ship_sig(uint64_t PC) {
    return (PC ^ (PC >> 6)) & (SHIP_SIG_ENTRIES - 1);
}

// Set up leader sets for DRRIP set-dueling
void InitLeaderSets() {
    for (uint32_t i = 0; i < LLC_SETS; ++i) {
        is_leader_set[i] = false;
        leader_is_srrip[i] = false;
    }
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i) {
        is_leader_set[i] = true;
        leader_is_srrip[i] = (i % 2 == 0); // half SRRIP, half BRRIP
    }
}

void InitReplacementState() {
    memset(repl_meta, 0, sizeof(repl_meta));
    memset(ship_ctr, SHIP_CTR_MAX, sizeof(ship_ctr)); // optimistic
    memset(stream_meta, 0, sizeof(stream_meta));
    psel = PSEL_MAX / 2;
    InitLeaderSets();
}

// Streaming detector: returns true if streaming detected
bool is_streaming(uint32_t set, uint64_t paddr) {
    StreamDetect &sd = stream_meta[set];
    int delta = (int)(paddr - sd.last_addr);
    sd.last_addr = paddr;
    sd.deltas[sd.idx] = delta;
    sd.idx = (sd.idx + 1) % STREAM_WIN_SIZE;

    // Check for near-monotonic deltas
    int monotonic = 0;
    for (int i = 1; i < STREAM_WIN_SIZE; ++i) {
        if (sd.deltas[i] == sd.deltas[i-1] && sd.deltas[i] != 0)
            monotonic++;
    }
    sd.stream_score = monotonic;
    return monotonic >= STREAM_DELTA_THRESHOLD;
}

// DRRIP: choose SRRIP or BRRIP insertion
inline uint8_t get_drrip_rrpv(uint32_t set) {
    if (is_leader_set[set]) {
        return leader_is_srrip[set] ? 2 : 3;
    }
    return (psel >= PSEL_MAX/2) ? 2 : 3;
}

// SHiP-lite: choose insertion RRPV based on signature
inline uint8_t get_ship_rrpv(uint8_t sig) {
    return (ship_ctr[sig] > 0) ? 2 : 3;
}

// Victim selection: standard RRPV
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Streaming bypass: if streaming detected, prefer distant RRPV
    if (is_streaming(set, paddr)) {
        // Find block with RRPV==RRPV_MAX
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (repl_meta[set][way].rrpv == RRPV_MAX)
                return way;
        }
        // If none, increment all RRPVs and retry
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            repl_meta[set][way].rrpv = std::min(RRPV_MAX, repl_meta[set][way].rrpv + 1);
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (repl_meta[set][way].rrpv == RRPV_MAX)
                return way;
        }
    } else {
        // Normal RRPV victim selection
        while (true) {
            for (uint32_t way = 0; way < LLC_WAYS; ++way) {
                if (repl_meta[set][way].rrpv == RRPV_MAX)
                    return way;
            }
            // Increment all RRPVs
            for (uint32_t way = 0; way < LLC_WAYS; ++way)
                repl_meta[set][way].rrpv = std::min(RRPV_MAX, repl_meta[set][way].rrpv + 1);
        }
    }
    // Should not reach here
    return 0;
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
    uint8_t sig = get_ship_sig(PC);

    // Streaming detector update already done in GetVictimInSet

    // On hit: promote block
    if (hit) {
        repl_meta[set][way].rrpv = 0;
        // SHiP: increment outcome counter (max SHIP_CTR_MAX)
        if (ship_ctr[sig] < SHIP_CTR_MAX)
            ship_ctr[sig]++;
    } else {
        // On fill: set signature
        repl_meta[set][way].ship_sig = sig;

        // DRRIP set-dueling: update PSEL on leader sets
        if (is_leader_set[set]) {
            if (leader_is_srrip[set]) {
                if (hit) {
                    if (psel < PSEL_MAX) psel++;
                }
            } else {
                if (hit) {
                    if (psel > 0) psel--;
                }
            }
        }

        // Streaming: if streaming detected, insert at distant RRPV
        if (is_streaming(set, paddr)) {
            repl_meta[set][way].rrpv = RRPV_MAX;
        } else {
            // SHiP + DRRIP: use SHiP outcome to bias insertion
            uint8_t ship_rrpv = get_ship_rrpv(sig);
            uint8_t drrip_rrpv = get_drrip_rrpv(set);
            repl_meta[set][way].rrpv = std::max(ship_rrpv, drrip_rrpv);
        }
    }

    // SHiP: On eviction, decrement outcome counter
    if (!hit) {
        uint8_t victim_sig = repl_meta[set][way].ship_sig;
        if (ship_ctr[victim_sig] > 0)
            ship_ctr[victim_sig]--;
    }
}

void PrintStats() {
    // Optional: print PSEL, SHiP stats
    std::cout << "Final PSEL: " << psel << std::endl;
}

void PrintStats_Heartbeat() {
    // Optional: print periodic stats
}