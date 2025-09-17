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
#define SIG_BITS 4 // per-line PC signature
#define SHIP_TABLE_ENTRIES 4096 // 4K entries
#define SHIP_COUNTER_BITS 2 // per-signature outcome
#define PSEL_BITS 10
#define LEADER_SETS 32
#define STREAM_DELTA_HISTORY 4
#define STREAM_DELTA_THRESHOLD 3

// --- Replacement State ---
struct LineState {
    uint8_t rrpv : RRPV_BITS;
    uint16_t sig : SIG_BITS; // 4 bits
};

struct StreamHistory {
    int64_t deltas[STREAM_DELTA_HISTORY];
    uint8_t ptr;
    bool streaming;
};

std::vector<LineState> line_state; // LLC_SETS * LLC_WAYS
std::vector<StreamHistory> stream_hist; // LLC_SETS
std::vector<uint64_t> last_addr; // LLC_SETS

// SHiP outcome table (compact: 2 bits/entry, 4K entries = 1KB)
std::vector<uint8_t> ship_table; // [SHIP_TABLE_ENTRIES] 2 bits

// Set-dueling leader sets
std::vector<uint8_t> is_leader_set; // LLC_SETS
uint16_t psel = 512; // 10-bit
uint64_t fill_count = 0;

// --- Helper Functions ---
inline uint16_t get_signature(uint64_t PC) {
    // Simple hash: CRC32, but only take lower 12 bits (SHIP_TABLE_ENTRIES)
    return champsim_crc32(PC) & (SHIP_TABLE_ENTRIES - 1);
}

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
    last_addr.resize(LLC_SETS, 0);
    ship_table.resize(SHIP_TABLE_ENTRIES, 1); // weakly positive
    is_leader_set.resize(LLC_SETS, 0);

    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        if (set < LEADER_SETS)
            is_leader_set[set] = 1;
        else if (set >= LLC_SETS - LEADER_SETS)
            is_leader_set[set] = 2;
        else
            is_leader_set[set] = 0;
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            line_state[set * LLC_WAYS + way].rrpv = RRPV_MAX;
            line_state[set * LLC_WAYS + way].sig = 0;
        }
        stream_hist[set].ptr = 0;
        stream_hist[set].streaming = false;
        memset(stream_hist[set].deltas, 0, sizeof(stream_hist[set].deltas));
    }
    psel = 512;
    fill_count = 0;
}

uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Streaming bypass: if streaming detected and SHiP outcome weak, bypass fill
    // NOTE: Victim selection still required for stats, but insertion may be bypassed in UpdateReplacementState
    uint32_t victim = LLC_WAYS;
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (line_state[set * LLC_WAYS + way].rrpv == RRPV_MAX) {
                victim = way;
                break;
            }
        }
        if (victim != LLC_WAYS)
            break;
        // Increment all RRPVs
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (line_state[set * LLC_WAYS + way].rrpv < RRPV_MAX)
                line_state[set * LLC_WAYS + way].rrpv++;
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
    int match = 0;
    for (uint8_t i = 1; i < STREAM_DELTA_HISTORY; ++i) {
        if (sh.deltas[i] == sh.deltas[0] && sh.deltas[0] != 0)
            match++;
    }
    sh.streaming = (match >= STREAM_DELTA_THRESHOLD);

    // --- SHiP signature ---
    uint16_t sig = get_signature(PC);

    // --- On hit ---
    if (hit) {
        // Reset RRPV to 0 (MRU)
        line_state[set * LLC_WAYS + way].rrpv = 0;
        // Update SHiP outcome counter (increment, saturate at 3)
        if (ship_table[sig] < 3) ship_table[sig]++;
        return;
    }

    // --- On fill ---
    // Streaming bypass logic: if streaming and SHiP weak (counter <=1), bypass fill
    if (sh.streaming && ship_table[sig] <= 1) {
        // Do not insert: act as bypass (do NOT update line_state)
        // Optionally: track bypass count, stats
        return;
    }

    // Determine insertion RRPV
    uint8_t insert_rrpv = RRPV_MAX - 1; // default SRRIP
    if (ship_table[sig] >= 2)
        insert_rrpv = 0; // SHiP: strong reuse, insert MRU
    else {
        // DRRIP set-dueling (SRRIP vs BRRIP)
        uint8_t use_srrip = 0;
        if (is_leader_set[set] == 1) use_srrip = 1;
        else if (is_leader_set[set] == 2) use_srrip = 0;
        else use_srrip = (psel >= 512);

        if (use_srrip)
            insert_rrpv = RRPV_MAX - 1; // SRRIP: 1
        else
            insert_rrpv = (rand() % 32 == 0) ? RRPV_MAX - 1 : RRPV_MAX; // BRRIP: 1/32 at 1, else max
    }

    line_state[set * LLC_WAYS + way].rrpv = insert_rrpv;
    line_state[set * LLC_WAYS + way].sig = sig; // track signature

    // --- On eviction: update SHiP outcome counter for evicted line's signature
    if (victim_addr) {
        uint16_t evict_sig = line_state[set * LLC_WAYS + way].sig;
        // If evicted block was not reused (RRPV==max), decrement SHiP counter
        if (line_state[set * LLC_WAYS + way].rrpv == RRPV_MAX && ship_table[evict_sig] > 0)
            ship_table[evict_sig]--;
    }

    // --- DRRIP set-dueling update ---
    if (is_leader_set[set] == 1 && !hit)
        psel = std::min((uint16_t)(psel + 1), (uint16_t)((1 << PSEL_BITS) - 1));
    else if (is_leader_set[set] == 2 && !hit)
        psel = (psel > 0) ? psel - 1 : 0;
}

void PrintStats() {
    std::cout << "SL-DRRIP-SB Policy: SHiP-lite DRRIP + streaming bypass\n";
}

void PrintStats_Heartbeat() {
    // Optionally print periodic stats
}