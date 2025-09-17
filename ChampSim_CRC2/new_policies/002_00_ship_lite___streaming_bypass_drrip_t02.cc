#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// DRRIP parameters
#define RRPV_BITS 2
#define MAX_RRPV ((1 << RRPV_BITS) - 1)
#define SHIP_SIG_BITS 6
#define SHIP_SIG_ENTRIES 4096 // 6 bits signature, 2 bits outcome
#define STREAM_DELTA_WIN 4    // Window for streaming detection
#define PSEL_BITS 10
#define PSEL_MAX ((1 << PSEL_BITS) - 1)
#define LEADER_SETS 64

// Replacement state
struct LineMeta {
    uint8_t rrpv; // 2 bits
    uint16_t ship_sig; // 6 bits
    uint8_t is_stream; // 1 bit
};

std::vector<std::vector<LineMeta>> repl_meta;
std::vector<uint64_t> last_addr_per_set(LLC_SETS, 0);
std::vector<uint64_t> last_delta_per_set(LLC_SETS, 0);
std::vector<uint8_t> stream_count_per_set(LLC_SETS, 0);

// SHiP-lite signature table: 4096 entries, 2 bits each
uint8_t ship_table[SHIP_SIG_ENTRIES];

// DRRIP set-dueling
uint16_t psel = PSEL_MAX / 2;
std::vector<uint8_t> is_srrip_leader(LLC_SETS, 0);
std::vector<uint8_t> is_brrip_leader(LLC_SETS, 0);

// Helper: get SHiP signature from PC
inline uint16_t get_ship_sig(uint64_t PC) {
    return (PC ^ (PC >> 6)) & (SHIP_SIG_ENTRIES - 1);
}

// Helper: assign leader sets for DRRIP
void assign_leader_sets() {
    for (uint32_t i = 0; i < LEADER_SETS; ++i) {
        is_srrip_leader[i] = 1;
        is_brrip_leader[LLC_SETS - 1 - i] = 1;
    }
}

// Initialize replacement state
void InitReplacementState() {
    repl_meta.resize(LLC_SETS, std::vector<LineMeta>(LLC_WAYS));
    memset(ship_table, 1, sizeof(ship_table)); // Start with weakly reused
    assign_leader_sets();
}

// Streaming detector: returns true if last N address deltas are near-monotonic
bool detect_streaming(uint32_t set, uint64_t paddr) {
    uint64_t last_addr = last_addr_per_set[set];
    uint64_t last_delta = last_delta_per_set[set];
    uint64_t delta = (last_addr == 0) ? 0 : paddr - last_addr;
    last_addr_per_set[set] = paddr;

    if (last_delta == 0) last_delta_per_set[set] = delta;
    else {
        if (delta == last_delta) {
            if (stream_count_per_set[set] < STREAM_DELTA_WIN)
                ++stream_count_per_set[set];
        } else {
            stream_count_per_set[set] = 0;
        }
        last_delta_per_set[set] = delta;
    }
    return stream_count_per_set[set] >= STREAM_DELTA_WIN;
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
    // Streaming detection
    bool is_stream = detect_streaming(set, paddr);

    // Find victim with MAX_RRPV
    for (uint32_t way = 0; way < LLC_WAYS; ++way) {
        if (repl_meta[set][way].rrpv == MAX_RRPV)
            return way;
    }
    // If none, increment RRPVs and retry
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        repl_meta[set][way].rrpv = std::min(MAX_RRPV, repl_meta[set][way].rrpv + 1);

    // Second pass
    for (uint32_t way = 0; way < LLC_WAYS; ++way) {
        if (repl_meta[set][way].rrpv == MAX_RRPV)
            return way;
    }
    // Fallback
    return 0;
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
    LineMeta &meta = repl_meta[set][way];
    uint16_t sig = get_ship_sig(PC);

    // Streaming detection
    bool is_stream = detect_streaming(set, paddr);
    meta.is_stream = is_stream ? 1 : 0;

    // On hit: update SHiP outcome
    if (hit) {
        ship_table[sig] = std::min((uint8_t)3, ship_table[sig] + 1);
        meta.rrpv = 0;
    } else {
        // On miss: set insertion RRPV
        uint8_t ins_rrpv;
        if (is_stream) {
            // Streaming: insert at distant RRPV (MAX_RRPV), likely bypass
            ins_rrpv = MAX_RRPV;
        } else {
            // Use SHiP outcome to bias insertion
            uint8_t outcome = ship_table[sig];
            if (outcome >= 2)
                ins_rrpv = 0; // High reuse: insert at MRU
            else
                ins_rrpv = MAX_RRPV - 1; // Low reuse: insert at distant
        }

        // DRRIP set-dueling: adjust insertion for leader sets
        if (is_srrip_leader[set])
            ins_rrpv = 2; // SRRIP: insert at 2
        else if (is_brrip_leader[set])
            ins_rrpv = (rand() % 32 == 0) ? 2 : MAX_RRPV; // BRRIP: mostly distant

        meta.rrpv = ins_rrpv;
        meta.ship_sig = sig;
    }

    // On eviction: update SHiP outcome
    if (!hit) {
        uint16_t victim_sig = repl_meta[set][way].ship_sig;
        if (victim_sig < SHIP_SIG_ENTRIES) {
            // If block was not reused, decrement outcome
            ship_table[victim_sig] = (ship_table[victim_sig] > 0) ? ship_table[victim_sig] - 1 : 0;
        }
    }

    // DRRIP PSEL update
    if (is_srrip_leader[set]) {
        if (hit) psel = (psel < PSEL_MAX) ? psel + 1 : PSEL_MAX;
        else     psel = (psel > 0) ? psel - 1 : 0;
    } else if (is_brrip_leader[set]) {
        if (hit) psel = (psel > 0) ? psel - 1 : 0;
        else     psel = (psel < PSEL_MAX) ? psel + 1 : PSEL_MAX;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "SHiP-Lite + Streaming Bypass DRRIP stats." << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Optionally print streaming detection rates, SHiP table stats, etc.
}