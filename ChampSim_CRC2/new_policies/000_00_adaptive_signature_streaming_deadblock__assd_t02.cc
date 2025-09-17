#include <vector>
#include <cstdint>
#include <cstring>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- Parameters ---
#define SHIP_SIG_BITS 5 // 32 entries per set
#define SHIP_SIG_ENTRIES 32
#define SHIP_SIG_MASK (SHIP_SIG_ENTRIES-1)
#define SHIP_SIG_COUNTER_BITS 2
#define DEAD_BLOCK_BITS 2
#define RRPV_BITS 2
#define STREAM_DELTA_HISTORY 4 // per-set
#define STREAM_DELTA_THRESHOLD 3 // monotonic if >=3/4 deltas match
#define PSEL_BITS 8
#define LEADER_SETS 32

// --- Replacement State ---
struct LineState {
    uint8_t rrpv : RRPV_BITS;
    uint8_t dead : DEAD_BLOCK_BITS;
};

struct SHIPEntry {
    uint8_t counter : SHIP_SIG_COUNTER_BITS;
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

uint8_t psel = 128; // 8-bit PSEL
std::vector<uint8_t> is_leader_srrip; // LLC_SETS

// --- Helper Functions ---
inline uint32_t get_ship_sig(uint64_t PC) {
    return (PC >> 2) & SHIP_SIG_MASK;
}

inline bool is_streaming_set(uint32_t set) {
    return stream_hist[set].streaming;
}

inline bool is_leader_set(uint32_t set) {
    // First LEADER_SETS for SRRIP, next LEADER_SETS for BRRIP
    if (set < LEADER_SETS) return 1; // SRRIP
    if (set >= LLC_SETS - LEADER_SETS) return 2; // BRRIP
    return 0;
}

// --- API Functions ---
void InitReplacementState() {
    line_state.resize(LLC_SETS * LLC_WAYS);
    ship_table.resize(LLC_SETS * SHIP_SIG_ENTRIES);
    stream_hist.resize(LLC_SETS);
    last_addr.resize(LLC_SETS, 0);
    is_leader_srrip.resize(LLC_SETS, 0);

    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        if (set < LEADER_SETS)
            is_leader_srrip[set] = 1; // SRRIP leader
        else if (set >= LLC_SETS - LEADER_SETS)
            is_leader_srrip[set] = 2; // BRRIP leader
        else
            is_leader_srrip[set] = 0; // follower
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            line_state[set * LLC_WAYS + way].rrpv = 3; // distant
            line_state[set * LLC_WAYS + way].dead = 0;
        }
        for (uint32_t i = 0; i < SHIP_SIG_ENTRIES; ++i)
            ship_table[set * SHIP_SIG_ENTRIES + i].counter = 1;
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
    // Streaming: bypass if detected
    if (is_streaming_set(set)) {
        // Find dead block if possible
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (line_state[set * LLC_WAYS + way].dead == 3)
                return way;
        }
        // Otherwise, evict max RRPV
        uint32_t victim = 0;
        uint8_t max_rrpv = 0;
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (line_state[set * LLC_WAYS + way].rrpv > max_rrpv) {
                max_rrpv = line_state[set * LLC_WAYS + way].rrpv;
                victim = way;
            }
        }
        return victim;
    }
    // Normal: prefer dead blocks, then max RRPV
    for (uint32_t way = 0; way < LLC_WAYS; ++way) {
        if (line_state[set * LLC_WAYS + way].dead == 3)
            return way;
    }
    uint32_t victim = 0;
    uint8_t max_rrpv = 0;
    for (uint32_t way = 0; way < LLC_WAYS; ++way) {
        if (line_state[set * LLC_WAYS + way].rrpv > max_rrpv) {
            max_rrpv = line_state[set * LLC_WAYS + way].rrpv;
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
    // Detect monotonic pattern
    int match = 0;
    for (uint8_t i = 1; i < STREAM_DELTA_HISTORY; ++i) {
        if (sh.deltas[i] == sh.deltas[0] && sh.deltas[0] != 0)
            match++;
    }
    sh.streaming = (match >= STREAM_DELTA_THRESHOLD);

    // --- Dead-block counter decay (every 256 fills) ---
    static uint64_t fill_count = 0;
    fill_count++;
    if ((fill_count & 0xFF) == 0) {
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            for (uint32_t w = 0; w < LLC_WAYS; ++w)
                if (line_state[s * LLC_WAYS + w].dead)
                    line_state[s * LLC_WAYS + w].dead--;
    }

    // --- SHiP signature ---
    uint32_t sig = get_ship_sig(PC);
    SHIPEntry &ship = ship_table[set * SHIP_SIG_ENTRIES + sig];

    // --- Set-dueling: choose insertion policy ---
    uint8_t use_srrip = 0;
    if (is_leader_srrip[set] == 1) use_srrip = 1;
    else if (is_leader_srrip[set] == 2) use_srrip = 0;
    else use_srrip = (psel >= 128);

    // --- On hit ---
    if (hit) {
        line_state[set * LLC_WAYS + way].rrpv = 0; // MRU
        if (line_state[set * LLC_WAYS + way].dead)
            line_state[set * LLC_WAYS + way].dead--;
        ship.counter = std::min((uint8_t)(ship.counter + 1), (uint8_t)((1 << SHIP_SIG_COUNTER_BITS) - 1));
        return;
    }

    // --- On fill ---
    // Streaming: bypass or insert at distant RRPV
    if (sh.streaming) {
        line_state[set * LLC_WAYS + way].rrpv = 3;
        line_state[set * LLC_WAYS + way].dead = 3;
        return;
    }

    // Dead-block: insert at distant RRPV
    if (line_state[set * LLC_WAYS + way].dead == 3) {
        line_state[set * LLC_WAYS + way].rrpv = 3;
        return;
    }

    // SHiP: strong reuse => insert at MRU
    if (ship.counter >= ((1 << SHIP_SIG_COUNTER_BITS) - 1)) {
        line_state[set * LLC_WAYS + way].rrpv = 0;
        line_state[set * LLC_WAYS + way].dead = 0;
    }
    // Moderate reuse: insert at mid RRPV
    else if (ship.counter >= 2) {
        line_state[set * LLC_WAYS + way].rrpv = 1;
        line_state[set * LLC_WAYS + way].dead = 1;
    }
    // Weak reuse: insert at distant RRPV
    else {
        line_state[set * LLC_WAYS + way].rrpv = use_srrip ? 2 : 3;
        line_state[set * LLC_WAYS + way].dead = 2;
    }

    // --- On eviction: update SHiP and dead-block ---
    if (victim_addr) {
        uint32_t victim_sig = get_ship_sig(PC);
        SHIPEntry &victim_ship = ship_table[set * SHIP_SIG_ENTRIES + victim_sig];
        // If block was not reused, decrement SHiP counter and mark dead
        if (!hit) {
            if (victim_ship.counter)
                victim_ship.counter--;
            line_state[set * LLC_WAYS + way].dead = 3;
        }
    }

    // --- Set-dueling update ---
    if (is_leader_srrip[set] == 1 && !hit)
        psel = std::min((uint8_t)(psel + 1), (uint8_t)((1 << PSEL_BITS) - 1));
    else if (is_leader_srrip[set] == 2 && !hit)
        psel = (psel > 0) ? psel - 1 : 0;
}

void PrintStats() {
    // Optionally print SHiP counters, streaming sets, dead-block stats
    std::cout << "ASSD Policy: SHiP, Streaming, Dead-block hybrid\n";
}

void PrintStats_Heartbeat() {
    // Optionally print periodic stats
}