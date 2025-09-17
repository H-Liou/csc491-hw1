#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- DRRIP set-dueling ---
#define NUM_LEADER_SETS 64
#define PSEL_MAX 1023
uint16_t PSEL = PSEL_MAX / 2;
bool is_sr_leader(uint32_t set) { return set % (LLC_SETS / NUM_LEADER_SETS) == 0; }
bool is_br_leader(uint32_t set) { return set % (LLC_SETS / NUM_LEADER_SETS) == 1; }

// --- Per-block: 2-bit RRPV, 6-bit SHiP signature ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];       // 2 bits per block
uint8_t signature[LLC_SETS][LLC_WAYS];  // 6 bits per block

// --- SHiP table: 8K entries × 2 bits = 16 KiB ---
#define SHIP_TABLE_SIZE 8192
uint8_t ship_table[SHIP_TABLE_SIZE];    // 2 bits per entry

// --- Streaming detector: 2-bit per set, last address/delta per set ---
uint8_t stream_ctr[LLC_SETS];
uint64_t last_addr[LLC_SETS];
uint64_t last_delta[LLC_SETS];

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv));
    memset(signature, 0, sizeof(signature));
    memset(ship_table, 1, sizeof(ship_table)); // neutral initial bias
    memset(stream_ctr, 0, sizeof(stream_ctr));
    memset(last_addr, 0, sizeof(last_addr));
    memset(last_delta, 0, sizeof(last_delta));
}

// --- Helper: get SHiP signature from PC ---
inline uint16_t get_signature(uint64_t PC) {
    // 6 bits: simple hash of PC
    return (PC ^ (PC >> 8) ^ (PC >> 16)) & 0x3F;
}

// --- Helper: SHiP table index ---
inline uint32_t ship_index(uint8_t sig) {
    // Use signature as index (6 bits), extend with set index for better spread
    // Here, we use (set lower 7 bits << 6) | sig for 8K entries
    return sig;
}

// --- Find victim: standard RRIP ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Find block with RRPV==3
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] < 3)
                rrpv[set][way]++;
    }
}

// --- Update replacement state ---
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
    // --- Streaming detector: update on fill (miss only) ---
    if (!hit) {
        uint64_t delta = (last_addr[set] == 0) ? 0 : (paddr - last_addr[set]);
        if (last_addr[set] != 0 && delta == last_delta[set] && delta != 0) {
            if (stream_ctr[set] < 3) stream_ctr[set]++;
        } else {
            if (stream_ctr[set] > 0) stream_ctr[set]--;
        }
        last_delta[set] = delta;
        last_addr[set] = paddr;
    }

    // --- SHiP signature ---
    uint8_t sig = get_signature(PC);

    // --- SHiP table index ---
    uint32_t ship_idx = (set & 0x7F) << 6 | sig; // 7 bits set + 6 bits sig = 13 bits (8K entries)
    ship_idx &= (SHIP_TABLE_SIZE - 1);

    // --- Streaming bypass logic ---
    bool streaming = (stream_ctr[set] >= 2);
    if (streaming) {
        // Streaming detected: bypass insertion (mark block as most distant)
        rrpv[set][way] = 3;
        signature[set][way] = sig;
        return;
    }

    // --- SHiP-Lite update ---
    if (hit) {
        // On hit: promote block, update SHiP table
        rrpv[set][way] = 0;
        signature[set][way] = sig;
        if (ship_table[ship_idx] < 3) ship_table[ship_idx]++;
        return;
    } else {
        // On miss: update SHiP table for victim block
        uint8_t victim_sig = signature[set][way];
        uint32_t victim_idx = (set & 0x7F) << 6 | victim_sig;
        victim_idx &= (SHIP_TABLE_SIZE - 1);
        if (ship_table[victim_idx] > 0) ship_table[victim_idx]--;
    }

    // --- DRRIP set-dueling: choose insertion depth ---
    uint8_t ins_rrpv = 2; // SRRIP default
    if (is_sr_leader(set)) {
        ins_rrpv = 2; // SRRIP
    } else if (is_br_leader(set)) {
        ins_rrpv = 3; // BRRIP
    } else {
        // Use PSEL to choose between SRRIP and BRRIP for follower sets
        ins_rrpv = (PSEL >= PSEL_MAX / 2) ? 2 : 3;
    }

    // --- SHiP-guided insertion depth ---
    if (ship_table[ship_idx] >= 2) {
        // High reuse: insert at RRPV=0 (long retention)
        ins_rrpv = 0;
    } else if (ship_table[ship_idx] == 1) {
        // Moderate reuse: insert at RRPV=2
        ins_rrpv = 2;
    } else {
        // Low reuse: insert at RRPV=3
        ins_rrpv = 3;
    }

    rrpv[set][way] = ins_rrpv;
    signature[set][way] = sig;

    // --- DRRIP set-dueling: update PSEL ---
    if (!streaming) {
        if (is_sr_leader(set) && hit) {
            if (PSEL < PSEL_MAX) PSEL++;
        } else if (is_br_leader(set) && hit) {
            if (PSEL > 0) PSEL--;
        }
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "SHiP-Lite DRRIP + Streaming Bypass: Final statistics." << std::endl;
    uint32_t streaming_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (stream_ctr[s] >= 2)
            streaming_sets++;
    std::cout << "Streaming sets at end: " << streaming_sets << "/" << LLC_SETS << std::endl;

    uint32_t high_reuse = 0;
    for (uint32_t i = 0; i < SHIP_TABLE_SIZE; ++i)
        if (ship_table[i] >= 2)
            high_reuse++;
    std::cout << "SHiP table high-reuse entries: " << high_reuse << "/" << SHIP_TABLE_SIZE << std::endl;

    std::cout << "PSEL final value: " << PSEL << " (SRRIP if high, BRRIP if low)" << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Optionally print streaming set count and SHiP table histogram
}