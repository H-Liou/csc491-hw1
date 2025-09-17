#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- Metadata structures ---
// 2 bits RRPV per block
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// 6-bit PC signature per block
uint8_t pc_sig[LLC_SETS][LLC_WAYS];

// SHiP-lite: 2-bit outcome counter per signature (64 entries per set)
uint8_t ship_ctr[LLC_SETS][64];

// Per-set streaming detector: 2-bit stride confidence, 8-bit last_addr, 8-bit last_delta
uint8_t stream_conf[LLC_SETS];
uint64_t stream_last_addr[LLC_SETS];
int16_t stream_last_delta[LLC_SETS];

// DIP set-dueling: 64 leader sets for LIP, 64 for BIP
#define NUM_LEADER_SETS 64
uint16_t PSEL = 512; // 10-bit counter
bool is_leader_lip[LLC_SETS];
bool is_leader_bip[LLC_SETS];

// --- Helper: get PC signature (6 bits) ---
inline uint8_t get_pc_sig(uint64_t PC) {
    // Use bits [4:9] of PC as signature
    return (PC >> 4) & 0x3F;
}

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv)); // All blocks start distant
    memset(pc_sig, 0, sizeof(pc_sig));
    memset(ship_ctr, 1, sizeof(ship_ctr)); // Initialize counters to weak reuse
    memset(stream_conf, 0, sizeof(stream_conf));
    memset(stream_last_addr, 0, sizeof(stream_last_addr));
    memset(stream_last_delta, 0, sizeof(stream_last_delta));

    // Assign leader sets for DIP set-dueling
    for (uint32_t s = 0; s < LLC_SETS; ++s) {
        if (s < NUM_LEADER_SETS)
            is_leader_lip[s] = true, is_leader_bip[s] = false;
        else if (s >= LLC_SETS - NUM_LEADER_SETS)
            is_leader_lip[s] = false, is_leader_bip[s] = true;
        else
            is_leader_lip[s] = false, is_leader_bip[s] = false;
    }
}

// --- Streaming detector update ---
inline bool detect_streaming(uint32_t set, uint64_t paddr) {
    int16_t delta = (int16_t)(paddr - stream_last_addr[set]);
    bool monotonic = (delta == stream_last_delta[set]) && (delta != 0);

    if (monotonic) {
        if (stream_conf[set] < 3) stream_conf[set]++;
    } else {
        if (stream_conf[set] > 0) stream_conf[set]--;
    }
    stream_last_delta[set] = delta;
    stream_last_addr[set] = paddr;

    // Streaming if confidence high
    return (stream_conf[set] >= 2);
}

// --- Find victim ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Standard RRIP victim selection: Pick block with RRPV==3, else increment all and retry
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (rrpv[set][way] == 3) {
                return way;
            }
        }
        // No block at RRPV==3, increment all (except max)
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (rrpv[set][way] < 3) rrpv[set][way]++;
        }
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
    // --- Streaming detector ---
    bool is_streaming = detect_streaming(set, paddr);

    // --- SHiP-lite signature ---
    uint8_t sig = get_pc_sig(PC);

    // --- On hit: increment outcome counter, protect block ---
    if (hit) {
        if (ship_ctr[set][sig] < 3) ship_ctr[set][sig]++;
        rrpv[set][way] = 0; // Most recently used
        return;
    }

    // --- On fill: update PC signature ---
    pc_sig[set][way] = sig;

    // --- On eviction: if block was not reused, decrement outcome counter ---
    uint8_t victim_sig = pc_sig[set][way];
    if (ship_ctr[set][victim_sig] > 0) ship_ctr[set][victim_sig]--;

    // --- DIP set-dueling: choose insertion depth ---
    uint8_t ins_rrpv = 3; // default: LIP (insert at distant)
    if (is_leader_lip[set]) {
        ins_rrpv = 3; // LIP: always distant
    } else if (is_leader_bip[set]) {
        ins_rrpv = (rand() % 32 == 0) ? 2 : 3; // BIP: mostly distant, sometimes long-term
    } else {
        // Use PSEL to select
        ins_rrpv = (PSEL >= 512) ? 3 : ((rand() % 32 == 0) ? 2 : 3);
    }

    // --- Streaming detector: if streaming, always insert at distant (or bypass) ---
    if (is_streaming) {
        ins_rrpv = 3; // Insert at distant, optionally bypass (never protect)
    }

    // --- SHiP-lite: if outcome counter for this sig is high, protect more ---
    if (ship_ctr[set][sig] >= 2 && !is_streaming) {
        ins_rrpv = 1; // Protect more aggressively if PC sig has proven reuse
    }

    // --- Insert block ---
    rrpv[set][way] = ins_rrpv;

    // --- DIP set-dueling: update PSEL ---
    if (is_leader_lip[set]) {
        if (hit && PSEL < 1023) PSEL++;
    } else if (is_leader_bip[set]) {
        if (hit && PSEL > 0) PSEL--;
    }
}

// --- Stats ---
void PrintStats() {
    std::cout << "SHiP-Lite-SHR Replacement Policy: Final statistics." << std::endl;
}

void PrintStats_Heartbeat() {
    // Optional: print streaming confidence histogram, SHiP counters, etc.
}