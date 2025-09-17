#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- Parameters ---
constexpr int SHIP_SIG_BITS = 12;  // 4K entries
constexpr int SHIP_SIG_ENTRIES = 1 << SHIP_SIG_BITS;
constexpr int SHIP_SIG_MASK = SHIP_SIG_ENTRIES - 1;
constexpr int SHIP_COUNTER_BITS = 2; // 2-bit outcome counter

constexpr int STREAM_DETECTOR_ENTRIES = LLC_SETS;
constexpr int STREAM_DELTA_HISTORY = 4; // Track last 4 deltas per set

constexpr int DEAD_BLOCK_COUNTER_BITS = 2; // 2-bit per line

// --- Replacement State ---
struct LineState {
    uint8_t rrpv; // 2-bit
    uint8_t dead_counter; // 2-bit dead block predictor
};

std::vector<std::vector<LineState>> repl_state(LLC_SETS, std::vector<LineState>(LLC_WAYS));

// SHiP-lite: per-PC signature table
struct ShipEntry {
    uint8_t counter; // 2 bits
};
ShipEntry ship_table[SHIP_SIG_ENTRIES];

// Streaming detector: per-set delta history
struct StreamDetectEntry {
    uint64_t last_addr;
    int deltas[STREAM_DELTA_HISTORY];
    int idx;
    bool streaming;
};
StreamDetectEntry stream_table[STREAM_DETECTOR_ENTRIES];

// --- Helper Functions ---
inline uint32_t get_signature(uint64_t PC) {
    // Simple hash: lower bits of PC
    return (PC ^ (PC >> 2)) & SHIP_SIG_MASK;
}

inline bool is_streaming(uint32_t set, uint64_t paddr) {
    StreamDetectEntry &sd = stream_table[set];
    int delta = static_cast<int>(paddr - sd.last_addr);
    sd.deltas[sd.idx] = delta;
    sd.idx = (sd.idx + 1) % STREAM_DELTA_HISTORY;
    sd.last_addr = paddr;
    // Check if last 4 deltas are identical and nonzero
    int ref = sd.deltas[0];
    if (ref == 0) return false;
    for (int i = 1; i < STREAM_DELTA_HISTORY; ++i)
        if (sd.deltas[i] != ref) return false;
    return true;
}

// --- API Functions ---
void InitReplacementState() {
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            repl_state[set][way].rrpv = 3; // Insert at distant RRPV
            repl_state[set][way].dead_counter = 0;
        }
        stream_table[set].last_addr = 0;
        memset(stream_table[set].deltas, 0, sizeof(stream_table[set].deltas));
        stream_table[set].idx = 0;
        stream_table[set].streaming = false;
    }
    for (int i = 0; i < SHIP_SIG_ENTRIES; ++i)
        ship_table[i].counter = 1; // Neutral start
}

uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Prefer blocks with RRPV==3; among those, prefer dead blocks (dead_counter==0)
    for (uint32_t round = 0; round < 2; ++round) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (repl_state[set][way].rrpv == 3) {
                if (round == 0 && repl_state[set][way].dead_counter == 0)
                    return way;
                else if (round == 1)
                    return way;
            }
        }
        // If no RRPV==3, increment all RRPVs
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (repl_state[set][way].rrpv < 3)
                repl_state[set][way].rrpv++;
    }
    // Fallback: evict way 0
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
    uint32_t sig = get_signature(PC);

    // Streaming detector
    bool streaming = is_streaming(set, paddr);

    if (hit) {
        // On hit: promote to RRPV=0, increment dead block counter
        repl_state[set][way].rrpv = 0;
        if (repl_state[set][way].dead_counter < (1 << DEAD_BLOCK_COUNTER_BITS) - 1)
            repl_state[set][way].dead_counter++;
        // SHiP outcome counter: increment if hot
        if (ship_table[sig].counter < 3)
            ship_table[sig].counter++;
    } else {
        // On fill: decide RRPV insertion depth
        if (streaming) {
            // Streaming scan: bypass, insert at RRPV=3
            repl_state[set][way].rrpv = 3;
        } else if (ship_table[sig].counter >= 2) {
            // Hot PC: insert at MRU (RRPV=0)
            repl_state[set][way].rrpv = 0;
        } else if (repl_state[set][way].dead_counter == 0) {
            // Dead block: insert at distant RRPV
            repl_state[set][way].rrpv = 3;
        } else {
            // Default: insert at near-MRU (RRPV=1)
            repl_state[set][way].rrpv = 1;
        }
        // Reset dead block counter
        repl_state[set][way].dead_counter = 0;
        // SHiP outcome counter: decay if cold
        if (ship_table[sig].counter > 0)
            ship_table[sig].counter--;
    }
}

void PrintStats() {
    // Optionally print SHiP hot/cold distribution
    int hot = 0, cold = 0;
    for (int i = 0; i < SHIP_SIG_ENTRIES; ++i) {
        if (ship_table[i].counter >= 2) hot++;
        else cold++;
    }
    std::cout << "HSRS SHiP hot/cold: " << hot << "/" << cold << std::endl;
}

void PrintStats_Heartbeat() {
    // No-op for brevity
}