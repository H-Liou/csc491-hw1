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
#define SHIP_SIG_BITS 5 // 5-bit PC signature per set
#define SHIP_TABLE_SIZE (LLC_SETS * 8) // 16K entries, fits in 32KiB (2 bits/entry)
#define SHIP_CTR_BITS 2
#define STREAM_DELTA_HISTORY 4
#define STREAM_DELTA_THRESHOLD 3
#define PSEL_BITS 10
#define LEADER_SETS 32

// --- Replacement State ---
struct LineState {
    uint8_t rrpv : RRPV_BITS;
    uint8_t ship_sig : SHIP_SIG_BITS;
};

struct StreamHistory {
    int64_t deltas[STREAM_DELTA_HISTORY];
    uint8_t ptr;
    bool streaming;
};

std::vector<LineState> line_state; // LLC_SETS * LLC_WAYS
std::vector<StreamHistory> stream_hist; // LLC_SETS
std::vector<uint64_t> last_addr; // LLC_SETS

// SHiP-lite table: 2 bits per entry, indexed by PC signature
std::vector<uint8_t> ship_ctr; // SHIP_TABLE_SIZE

uint16_t psel = 512; // 10-bit PSEL, midpoint

std::vector<uint8_t> is_leader_set; // LLC_SETS

// --- Helper Functions ---
inline uint8_t get_leader_type(uint32_t set) {
    if (set < LEADER_SETS) return 1; // SRRIP leader
    if (set >= LLC_SETS - LEADER_SETS) return 2; // BRRIP leader
    return 0;
}

inline uint16_t get_ship_index(uint64_t PC) {
    // Use lower SHIP_SIG_BITS of PC, xor with set index for diversity
    return ((PC >> 2) ^ (PC >> 11)) & (SHIP_TABLE_SIZE - 1);
}

inline bool is_streaming_set(uint32_t set) {
    return stream_hist[set].streaming;
}

// --- API Functions ---
void InitReplacementState() {
    line_state.resize(LLC_SETS * LLC_WAYS);
    stream_hist.resize(LLC_SETS);
    last_addr.resize(LLC_SETS, 0);
    ship_ctr.resize(SHIP_TABLE_SIZE, 1); // Initialize to weak reuse
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
            line_state[set * LLC_WAYS + way].ship_sig = 0;
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
    // Streaming: prefer not to insert, but if must, evict oldest
    if (is_streaming_set(set)) {
        // Pick block with RRPV==max
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (line_state[set * LLC_WAYS + way].rrpv == RRPV_MAX)
                return way;
        // If none, increment all RRPVs and retry
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (line_state[set * LLC_WAYS + way].rrpv < RRPV_MAX)
                line_state[set * LLC_WAYS + way].rrpv++;
        // Try again
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (line_state[set * LLC_WAYS + way].rrpv == RRPV_MAX)
                return way;
        // Fallback: evict way 0
        return 0;
    }
    // Standard RRIP victim selection
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (line_state[set * LLC_WAYS + way].rrpv == RRPV_MAX)
                return way;
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

    // --- SHiP-lite index ---
    uint16_t ship_idx = get_ship_index(PC);

    // --- On hit ---
    if (hit) {
        // Reset RRPV to 0 (MRU)
        line_state[set * LLC_WAYS + way].rrpv = 0;
        // Update SHiP counter for this signature (increment, saturate)
        if (ship_ctr[ship_idx] < ((1 << SHIP_CTR_BITS) - 1))
            ship_ctr[ship_idx]++;
        return;
    }

    // --- On fill ---
    // Streaming: bypass insertion
    if (sh.streaming) {
        // Do not insert the block (simulate bypass by not updating state)
        line_state[set * LLC_WAYS + way].rrpv = RRPV_MAX;
        line_state[set * LLC_WAYS + way].ship_sig = ship_idx & ((1 << SHIP_SIG_BITS) - 1);
        return;
    }

    // Use SHiP counter to bias insertion
    uint8_t insert_rrpv = RRPV_MAX - 1; // default SRRIP
    if (ship_ctr[ship_idx] <= 1) {
        // Low reuse: insert at distant RRPV (BRRIP-max)
        insert_rrpv = RRPV_MAX;
    } else if (ship_ctr[ship_idx] == 2) {
        // Moderate reuse: DRRIP set-dueling
        uint8_t use_srrip = 0;
        if (is_leader_set[set] == 1) use_srrip = 1;
        else if (is_leader_set[set] == 2) use_srrip = 0;
        else use_srrip = (psel >= 512);
        if (use_srrip)
            insert_rrpv = RRPV_MAX - 1; // SRRIP
        else
            insert_rrpv = (rand() % 32 == 0) ? RRPV_MAX - 1 : RRPV_MAX; // BRRIP
    } else {
        // High reuse: insert at SRRIP-0 (MRU)
        insert_rrpv = 0;
    }

    line_state[set * LLC_WAYS + way].rrpv = insert_rrpv;
    line_state[set * LLC_WAYS + way].ship_sig = ship_idx & ((1 << SHIP_SIG_BITS) - 1);

    // --- On eviction: update SHiP counter ---
    if (victim_addr) {
        // If evicted block was not reused (RRPV==max), decrement SHiP counter
        if (line_state[set * LLC_WAYS + way].rrpv == RRPV_MAX) {
            if (ship_ctr[ship_idx] > 0)
                ship_ctr[ship_idx]--;
        }
    }

    // --- DRRIP set-dueling update ---
    if (is_leader_set[set] == 1 && !hit)
        psel = std::min((uint16_t)(psel + 1), (uint16_t)((1 << PSEL_BITS) - 1));
    else if (is_leader_set[set] == 2 && !hit)
        psel = (psel > 0) ? psel - 1 : 0;
}

void PrintStats() {
    std::cout << "SL-DRRIP-SB Policy: SHiP-lite + DRRIP set-dueling + streaming bypass\n";
}

void PrintStats_Heartbeat() {
    // Optionally print periodic stats
}