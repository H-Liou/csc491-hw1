#include <vector>
#include <cstdint>
#include <cstring>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- SHiP-lite parameters ---
#define SHIP_SIG_BITS 6
#define SHIP_SIG_ENTRIES (1 << SHIP_SIG_BITS)
#define SHIP_OUTCOME_BITS 2

// --- DRRIP parameters ---
#define RRPV_BITS 2
#define MAX_RRPV ((1 << RRPV_BITS) - 1)
#define PSEL_BITS 10
#define PSEL_MAX ((1 << PSEL_BITS) - 1)
#define NUM_LEADER_SETS 64

// --- Streaming detector parameters ---
#define STREAM_DELTA_HISTORY 4
#define STREAM_DELTA_THRESHOLD 3

// --- Metadata ---
struct SHIPEntry {
    uint8_t outcome; // 2 bits
};

struct StreamingInfo {
    uint64_t last_addr;
    int64_t deltas[STREAM_DELTA_HISTORY];
    uint8_t idx;
    uint8_t stream_score;
};

struct ReplacementState {
    uint8_t rrpv[LLC_SETS][LLC_WAYS];
    SHIPEntry ship_table[SHIP_SIG_ENTRIES];
    StreamingInfo stream_info[LLC_SETS];
    uint16_t psel;
    uint8_t set_type[LLC_SETS]; // 0: follower, 1: SRRIP leader, 2: BRRIP leader
};

ReplacementState repl;

// Helper: get SHiP signature
inline uint16_t get_signature(uint64_t PC) {
    return (PC ^ (PC >> 2)) & (SHIP_SIG_ENTRIES - 1);
}

// Helper: set type assignment
void assign_set_types() {
    for (uint32_t s = 0; s < LLC_SETS; ++s) {
        if (s < NUM_LEADER_SETS)
            repl.set_type[s] = 1; // SRRIP leader
        else if (s >= LLC_SETS - NUM_LEADER_SETS)
            repl.set_type[s] = 2; // BRRIP leader
        else
            repl.set_type[s] = 0; // follower
    }
}

// Initialize replacement state
void InitReplacementState() {
    memset(&repl, 0, sizeof(repl));
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        for (uint32_t w = 0; w < LLC_WAYS; ++w)
            repl.rrpv[s][w] = MAX_RRPV;
    assign_set_types();
    repl.psel = PSEL_MAX / 2;
}

// Streaming detector: returns true if streaming detected
bool is_streaming(uint32_t set, uint64_t paddr) {
    StreamingInfo &info = repl.stream_info[set];
    int64_t delta = (int64_t)paddr - (int64_t)info.last_addr;
    info.deltas[info.idx] = delta;
    info.idx = (info.idx + 1) % STREAM_DELTA_HISTORY;
    info.last_addr = paddr;

    // Check for monotonic deltas
    int score = 0;
    for (int i = 1; i < STREAM_DELTA_HISTORY; ++i)
        if (info.deltas[i] == info.deltas[0])
            ++score;
    if (score >= STREAM_DELTA_THRESHOLD) {
        info.stream_score = std::min<uint8_t>(info.stream_score + 1, 7);
    } else {
        info.stream_score = info.stream_score > 0 ? info.stream_score - 1 : 0;
    }
    return info.stream_score >= 3;
}

// Find victim in the set
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Standard RRPV victim selection
    while (true) {
        for (uint32_t w = 0; w < LLC_WAYS; ++w)
            if (repl.rrpv[set][w] == MAX_RRPV)
                return w;
        // Increment all RRPVs
        for (uint32_t w = 0; w < LLC_WAYS; ++w)
            if (repl.rrpv[set][w] < MAX_RRPV)
                ++repl.rrpv[set][w];
    }
}

// Update replacement state
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
    // Streaming detection
    bool streaming = is_streaming(set, paddr);

    // SHiP signature
    uint16_t sig = get_signature(PC);

    // On hit: promote
    if (hit) {
        repl.rrpv[set][way] = 0;
        // SHiP: increment outcome counter
        if (repl.ship_table[sig].outcome < ((1 << SHIP_OUTCOME_BITS) - 1))
            ++repl.ship_table[sig].outcome;
        return;
    }

    // On fill: decide insertion depth
    uint8_t ins_rrpv = MAX_RRPV; // default distant

    if (streaming) {
        // Streaming detected: bypass or insert at distant RRPV
        ins_rrpv = MAX_RRPV;
    } else {
        // SHiP outcome: if outcome counter high, insert at RRPV=0, else distant
        if (repl.ship_table[sig].outcome >= ((1 << SHIP_OUTCOME_BITS) / 2))
            ins_rrpv = 0;
        else {
            // DRRIP set-dueling
            if (repl.set_type[set] == 1) // SRRIP leader
                ins_rrpv = 2;
            else if (repl.set_type[set] == 2) // BRRIP leader
                ins_rrpv = MAX_RRPV;
            else // follower
                ins_rrpv = (repl.psel >= (PSEL_MAX / 2)) ? 2 : MAX_RRPV;
        }
    }
    repl.rrpv[set][way] = ins_rrpv;

    // Update PSEL for leader sets
    if (!streaming) {
        if (repl.set_type[set] == 1) { // SRRIP leader
            if (hit && repl.psel < PSEL_MAX) ++repl.psel;
        } else if (repl.set_type[set] == 2) { // BRRIP leader
            if (hit && repl.psel > 0) --repl.psel;
        }
    }

    // SHiP: on eviction, decay outcome counter
    if (!hit) {
        if (repl.ship_table[get_signature(victim_addr)].outcome > 0)
            --repl.ship_table[get_signature(victim_addr)].outcome;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "SHiP-Lite + Streaming Bypass DRRIP stats: PSEL=" << repl.psel << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Optionally print streaming detection rates, etc.
}