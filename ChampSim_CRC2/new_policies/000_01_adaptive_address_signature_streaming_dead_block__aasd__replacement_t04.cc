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

// 6-bit address signature per block
uint8_t addr_sig[LLC_SETS][LLC_WAYS];

// 2-bit reuse counter per block (dead-block approx)
uint8_t reuse_counter[LLC_SETS][LLC_WAYS];

// Per-set streaming detector: 2-bit stride confidence, 8-bit last_addr, 8-bit last_delta
uint8_t stream_conf[LLC_SETS];
uint64_t stream_last_addr[LLC_SETS];
int16_t stream_last_delta[LLC_SETS];

// DRRIP set-dueling: 64 leader sets for SRRIP, 64 for BRRIP
#define NUM_LEADER_SETS 64
uint16_t PSEL = 512; // 10-bit counter
bool is_leader_srrip[LLC_SETS];
bool is_leader_brrip[LLC_SETS];

// --- Helper: get address signature (6 bits) ---
inline uint8_t get_addr_sig(uint64_t paddr) {
    // Use bits [12:17] of address as signature (page offset granularity)
    return (paddr >> 12) & 0x3F;
}

// --- Initialization ---
void InitReplacementState() {
    // Zero all metadata
    memset(rrpv, 3, sizeof(rrpv)); // All blocks start distant
    memset(addr_sig, 0, sizeof(addr_sig));
    memset(reuse_counter, 0, sizeof(reuse_counter));
    memset(stream_conf, 0, sizeof(stream_conf));
    memset(stream_last_addr, 0, sizeof(stream_last_addr));
    memset(stream_last_delta, 0, sizeof(stream_last_delta));

    // Assign leader sets for DRRIP set-dueling
    for (uint32_t s = 0; s < LLC_SETS; ++s) {
        if (s < NUM_LEADER_SETS)
            is_leader_srrip[s] = true;
        else if (s >= LLC_SETS - NUM_LEADER_SETS)
            is_leader_brrip[s] = true;
        else {
            is_leader_srrip[s] = false;
            is_leader_brrip[s] = false;
        }
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

    // --- Address signature predictor ---
    uint8_t sig = get_addr_sig(paddr);

    // --- Dead-block counter decay (periodic) ---
    static uint64_t access_counter = 0;
    access_counter++;
    if ((access_counter & 0x3FFF) == 0) { // Every 16K accesses, decay all reuse counters
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            for (uint32_t w = 0; w < LLC_WAYS; ++w)
                if (reuse_counter[s][w] > 0) reuse_counter[s][w]--;
    }

    // --- On hit: increment reuse counter, protect block ---
    if (hit) {
        if (reuse_counter[set][way] < 3) reuse_counter[set][way]++;
        // SRRIP: set RRPV to 0 (most recently used)
        rrpv[set][way] = 0;
        return;
    }

    // --- On fill: update address signature, reuse counter ---
    addr_sig[set][way] = sig;
    // If block was evicted without reuse, reset reuse counter
    if (reuse_counter[set][way] == 0) {
        // Dead-on-arrival block, keep at 0
    } else {
        // Decay reuse counter for new fill
        reuse_counter[set][way] >>= 1;
    }

    // --- DRRIP set-dueling: choose insertion depth ---
    uint8_t ins_rrpv = 2; // default: SRRIP (long-term protection)
    if (is_leader_srrip[set]) {
        ins_rrpv = 2;
    } else if (is_leader_brrip[set]) {
        ins_rrpv = (rand() % 32 == 0) ? 2 : 3; // BRRIP: distant most of the time
    } else {
        // Use PSEL to select
        ins_rrpv = (PSEL >= 512) ? 2 : ((rand() % 32 == 0) ? 2 : 3);
    }

    // --- Streaming detector: if streaming, bypass or insert distant ---
    if (is_streaming) {
        ins_rrpv = 3; // Insert at distant, or optionally bypass (never protect)
    }

    // --- Address signature reuse: if reuse counter for this sig is high, protect ---
    // Scan set for matching sig
    bool sig_high_reuse = false;
    for (uint32_t w = 0; w < LLC_WAYS; ++w) {
        if (addr_sig[set][w] == sig && reuse_counter[set][w] >= 2)
            sig_high_reuse = true;
    }
    if (sig_high_reuse && !is_streaming) {
        ins_rrpv = 1; // Protect more aggressively if address sig has reuse
    }

    // --- Insert block ---
    rrpv[set][way] = ins_rrpv;

    // --- DRRIP set-dueling: update PSEL ---
    if (is_leader_srrip[set]) {
        if (hit) {
            if (PSEL < 1023) PSEL++;
        }
    } else if (is_leader_brrip[set]) {
        if (hit) {
            if (PSEL > 0) PSEL--;
        }
    }
}

// --- Stats ---
void PrintStats() {
    std::cout << "AASD Replacement Policy: Final statistics." << std::endl;
}

void PrintStats_Heartbeat() {
    // Optional: print streaming confidence histogram, reuse counter stats, etc.
}