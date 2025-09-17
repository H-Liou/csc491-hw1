#include <vector>
#include <cstdint>
#include <cstring>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- Parameters ---
#define SHIP_SIG_BITS 6 // 64 entries per set
#define SHIP_SIG_ENTRIES (1 << SHIP_SIG_BITS)
#define SHIP_SIG_MASK (SHIP_SIG_ENTRIES-1)
#define SHIP_SIG_COUNTER_BITS 2
#define STREAM_DELTA_HISTORY 4 // per-set
#define STREAM_DELTA_THRESHOLD 3 // monotonic if >=3/4 deltas match
#define PSEL_BITS 10
#define LEADER_SETS 32
#define BIP_PROB 32 // Insert at MRU with probability 1/32

// --- Replacement State ---
struct LineState {
    uint8_t lru; // 4 bits: 0 (MRU) ... 15 (LRU)
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

uint16_t psel = 512; // 10-bit PSEL, midpoint
std::vector<uint8_t> is_leader_set; // LLC_SETS

// --- Helper Functions ---
inline uint32_t get_ship_sig(uint64_t PC) {
    return (PC >> 2) & SHIP_SIG_MASK;
}

inline bool is_streaming_set(uint32_t set) {
    return stream_hist[set].streaming;
}

inline uint8_t get_leader_type(uint32_t set) {
    // First LEADER_SETS for LIP, last LEADER_SETS for BIP, rest are followers
    if (set < LEADER_SETS) return 1; // LIP leader
    if (set >= LLC_SETS - LEADER_SETS) return 2; // BIP leader
    return 0;
}

// --- API Functions ---
void InitReplacementState() {
    line_state.resize(LLC_SETS * LLC_WAYS);
    ship_table.resize(LLC_SETS * SHIP_SIG_ENTRIES);
    stream_hist.resize(LLC_SETS);
    last_addr.resize(LLC_SETS, 0);
    is_leader_set.resize(LLC_SETS, 0);

    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        if (set < LEADER_SETS)
            is_leader_set[set] = 1; // LIP leader
        else if (set >= LLC_SETS - LEADER_SETS)
            is_leader_set[set] = 2; // BIP leader
        else
            is_leader_set[set] = 0; // follower
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            line_state[set * LLC_WAYS + way].lru = LLC_WAYS - 1; // LRU
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
    // Streaming: bypass (return invalid way)
    if (is_streaming_set(set))
        return LLC_WAYS; // bypass, no replacement

    // Find LRU block
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
    // Detect monotonic pattern
    int match = 0;
    for (uint8_t i = 1; i < STREAM_DELTA_HISTORY; ++i) {
        if (sh.deltas[i] == sh.deltas[0] && sh.deltas[0] != 0)
            match++;
    }
    sh.streaming = (match >= STREAM_DELTA_THRESHOLD);

    // --- SHiP signature ---
    uint32_t sig = get_ship_sig(PC);
    SHIPEntry &ship = ship_table[set * SHIP_SIG_ENTRIES + sig];

    // --- DIP set-dueling: choose insertion policy ---
    uint8_t use_lip = 0;
    if (is_leader_set[set] == 1) use_lip = 1;
    else if (is_leader_set[set] == 2) use_lip = 0;
    else use_lip = (psel >= 512);

    // --- On hit ---
    if (hit) {
        // Move to MRU
        uint8_t old_lru = line_state[set * LLC_WAYS + way].lru;
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            if (line_state[set * LLC_WAYS + w].lru < old_lru)
                line_state[set * LLC_WAYS + w].lru++;
        }
        line_state[set * LLC_WAYS + way].lru = 0;
        // SHiP: increment counter
        ship.counter = std::min((uint8_t)(ship.counter + 1), (uint8_t)((1 << SHIP_SIG_COUNTER_BITS) - 1));
        return;
    }

    // --- On fill ---
    if (sh.streaming) {
        // Streaming: bypass fill (do not update replacement state)
        return;
    }

    // SHiP: strong reuse => BIP (insert at MRU with low probability)
    if (ship.counter >= ((1 << SHIP_SIG_COUNTER_BITS) - 1)) {
        // BIP: insert at MRU with probability 1/BIP_PROB, else at LRU
        if ((rand() % BIP_PROB) == 0) {
            // Insert at MRU
            uint8_t old_lru = line_state[set * LLC_WAYS + way].lru;
            for (uint32_t w = 0; w < LLC_WAYS; ++w) {
                if (line_state[set * LLC_WAYS + w].lru < old_lru)
                    line_state[set * LLC_WAYS + w].lru++;
            }
            line_state[set * LLC_WAYS + way].lru = 0;
        } else {
            // Insert at LRU
            uint8_t old_lru = line_state[set * LLC_WAYS + way].lru;
            for (uint32_t w = 0; w < LLC_WAYS; ++w) {
                if (line_state[set * LLC_WAYS + w].lru < old_lru)
                    line_state[set * LLC_WAYS + w].lru++;
            }
            line_state[set * LLC_WAYS + way].lru = LLC_WAYS - 1;
        }
    }
    // Moderate reuse: DIP policy (LIP/BIP set-dueling)
    else if (ship.counter >= 2) {
        if (use_lip) {
            // LIP: insert at LRU
            uint8_t old_lru = line_state[set * LLC_WAYS + way].lru;
            for (uint32_t w = 0; w < LLC_WAYS; ++w) {
                if (line_state[set * LLC_WAYS + w].lru < old_lru)
                    line_state[set * LLC_WAYS + w].lru++;
            }
            line_state[set * LLC_WAYS + way].lru = LLC_WAYS - 1;
        } else {
            // BIP: insert at MRU with probability 1/BIP_PROB
            if ((rand() % BIP_PROB) == 0) {
                uint8_t old_lru = line_state[set * LLC_WAYS + way].lru;
                for (uint32_t w = 0; w < LLC_WAYS; ++w) {
                    if (line_state[set * LLC_WAYS + w].lru < old_lru)
                        line_state[set * LLC_WAYS + w].lru++;
                }
                line_state[set * LLC_WAYS + way].lru = 0;
            } else {
                uint8_t old_lru = line_state[set * LLC_WAYS + way].lru;
                for (uint32_t w = 0; w < LLC_WAYS; ++w) {
                    if (line_state[set * LLC_WAYS + w].lru < old_lru)
                        line_state[set * LLC_WAYS + w].lru++;
                }
                line_state[set * LLC_WAYS + way].lru = LLC_WAYS - 1;
            }
        }
    }
    // Weak reuse: always LIP (insert at LRU)
    else {
        uint8_t old_lru = line_state[set * LLC_WAYS + way].lru;
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            if (line_state[set * LLC_WAYS + w].lru < old_lru)
                line_state[set * LLC_WAYS + w].lru++;
        }
        line_state[set * LLC_WAYS + way].lru = LLC_WAYS - 1;
    }

    // --- On eviction: update SHiP ---
    if (victim_addr) {
        uint32_t victim_sig = get_ship_sig(PC);
        SHIPEntry &victim_ship = ship_table[set * SHIP_SIG_ENTRIES + victim_sig];
        // If block was not reused, decrement SHiP counter
        if (!hit && victim_ship.counter)
            victim_ship.counter--;
    }

    // --- DIP set-dueling update ---
    if (is_leader_set[set] == 1 && !hit)
        psel = std::min((uint16_t)(psel + 1), (uint16_t)((1 << PSEL_BITS) - 1));
    else if (is_leader_set[set] == 2 && !hit)
        psel = (psel > 0) ? psel - 1 : 0;
}

void PrintStats() {
    std::cout << "SDISB Policy: SHiP signature, DIP set-dueling, Streaming bypass\n";
}

void PrintStats_Heartbeat() {
    // Optionally print periodic stats
}