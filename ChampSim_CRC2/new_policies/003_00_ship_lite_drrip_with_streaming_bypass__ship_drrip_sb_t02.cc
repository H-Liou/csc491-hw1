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
#define PSEL_BITS 10
#define LEADER_SETS 32

// --- Replacement State ---
struct LineState {
    uint8_t rrpv : RRPV_BITS;
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

// DRRIP set-dueling
std::vector<uint8_t> is_leader_set; // LLC_SETS
uint16_t psel = 512; // 10-bit PSEL, midpoint

// --- Helper Functions ---
inline uint8_t get_leader_type(uint32_t set) {
    if (set < LEADER_SETS) return 1; // SRRIP leader
    if (set >= LLC_SETS - LEADER_SETS) return 2; // BRRIP leader
    return 0;
}

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
            line_state[set * LLC_WAYS + way].signature = 0;
        }
        stream_hist[set].ptr = 0;
        stream_hist[set].streaming = false;
        memset(stream_hist[set].deltas, 0, sizeof(stream_hist[set].deltas));
    }
    psel = 512;
}

uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Streaming: bypass fills, but must select a victim for stats
    if (is_streaming_set(set)) {
        // Pick oldest RRPV
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (line_state[set * LLC_WAYS + way].rrpv == RRPV_MAX)
                return way;
        // If none, increment all and retry
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (line_state[set * LLC_WAYS + way].rrpv < RRPV_MAX)
                line_state[set * LLC_WAYS + way].rrpv++;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (line_state[set * LLC_WAYS + way].rrpv == RRPV_MAX)
                return way;
        return 0;
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

    // --- SHiP-lite signature ---
    uint16_t sig = get_signature(PC);

    // --- On hit ---
    if (hit) {
        // Reset RRPV to 0 (MRU)
        line_state[set * LLC_WAYS + way].rrpv = 0;
        // Update SHiP outcome: increment reuse counter
        if (ship_table[sig] < 3)
            ship_table[sig]++;
        return;
    }

    // --- Streaming: bypass fill ---
    if (sh.streaming) {
        // Do not fill cache (simulate bypass)
        return;
    }

    // --- On fill ---
    uint8_t insert_rrpv = RRPV_MAX; // default: distant

    // Use SHiP-lite outcome to bias insertion
    if (ship_table[sig] >= 2)
        insert_rrpv = RRPV_MAX - 1; // likely reused, insert at SRRIP-1
    else
        insert_rrpv = RRPV_MAX; // likely dead, insert at SRRIP-max

    // For leader sets, use DRRIP set-dueling
    if (is_leader_set[set] == 1)
        insert_rrpv = RRPV_MAX - 1; // SRRIP
    else if (is_leader_set[set] == 2)
        insert_rrpv = (rand() % 32 == 0) ? RRPV_MAX - 1 : RRPV_MAX; // BRRIP

    line_state[set * LLC_WAYS + way].rrpv = insert_rrpv;
    line_state[set * LLC_WAYS + way].signature = sig;

    // --- On eviction: update SHiP outcome ---
    if (victim_addr) {
        uint16_t victim_sig = line_state[set * LLC_WAYS + way].signature;
        // If evicted block was not reused (RRPV==max), decrement reuse counter
        if (line_state[set * LLC_WAYS + way].rrpv == RRPV_MAX && ship_table[victim_sig] > 0)
            ship_table[victim_sig]--;
    }

    // --- DRRIP set-dueling update ---
    if (is_leader_set[set] == 1 && !hit)
        psel = std::min((uint16_t)(psel + 1), (uint16_t)((1 << PSEL_BITS) - 1));
    else if (is_leader_set[set] == 2 && !hit)
        psel = (psel > 0) ? psel - 1 : 0;
}

void PrintStats() {
    std::cout << "SHiP-DRRIP-SB Policy: SHiP-lite signature insertion + DRRIP set-dueling + streaming bypass\n";
}

void PrintStats_Heartbeat() {
    // Optionally print periodic stats
}