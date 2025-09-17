#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- DIP Set-Dueling: 32 leader sets for LIP, 32 for BIP ---
#define NUM_LEADER_SETS 32
uint16_t PSEL = 512; // 10-bit selector
bool is_leader_lip[LLC_SETS];
bool is_leader_bip[LLC_SETS];

// --- Dead-block predictor: 2-bit per line, periodic decay ---
// 2 bits per line: 0=dead, 3=recently reused
uint8_t deadblock_reuse[LLC_SETS][LLC_WAYS];

// --- Streaming filter: per-set, 2-entry address history, 2-bit counter ---
uint64_t stream_addr_hist[LLC_SETS][2]; // last two addresses per set
uint8_t stream_delta_hist[LLC_SETS][2]; // last two deltas per set (low bits)
uint8_t stream_counter[LLC_SETS];       // per-set streaming confidence (2 bits)

// --- RRPV: 2 bits per block (for recency tracking) ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// --- Decay interval for dead-block predictor ---
#define DEADBLOCK_DECAY_INTERVAL 8192
uint64_t dbp_access_count = 0;

// --- Initialization ---
void InitReplacementState() {
    memset(deadblock_reuse, 0, sizeof(deadblock_reuse));
    memset(rrpv, 3, sizeof(rrpv));
    memset(is_leader_lip, 0, sizeof(is_leader_lip));
    memset(is_leader_bip, 0, sizeof(is_leader_bip));
    memset(stream_addr_hist, 0, sizeof(stream_addr_hist));
    memset(stream_delta_hist, 0, sizeof(stream_delta_hist));
    memset(stream_counter, 0, sizeof(stream_counter));
    PSEL = 512;
    dbp_access_count = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s) {
        if (s < NUM_LEADER_SETS)
            is_leader_lip[s] = true;
        else if (s >= LLC_SETS - NUM_LEADER_SETS)
            is_leader_bip[s] = true;
    }
}

// --- Find victim: standard SRRIP ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Standard SRRIP victim selection
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
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
    dbp_access_count++;

    // --- Dead-block predictor update ---
    // On hit, increment reuse counter
    if (hit) {
        if (deadblock_reuse[set][way] < 3)
            deadblock_reuse[set][way]++;
        rrpv[set][way] = 0; // promote to MRU on hit

        // DIP set-dueling PSEL update
        if (is_leader_lip[set]) {
            if (PSEL < 1023) PSEL++;
        } else if (is_leader_bip[set]) {
            if (PSEL > 0) PSEL--;
        }
        return;
    }

    // --- Streaming filter update ---
    uint64_t prev_addr = stream_addr_hist[set][1];
    uint8_t prev_delta = stream_delta_hist[set][1];
    uint8_t cur_delta = (uint8_t)((paddr >> 6) - (stream_addr_hist[set][0] >> 6));

    // Shift history
    stream_addr_hist[set][1] = stream_addr_hist[set][0];
    stream_addr_hist[set][0] = paddr;
    stream_delta_hist[set][1] = stream_delta_hist[set][0];
    stream_delta_hist[set][0] = cur_delta;

    // Streaming detection: if last two deltas are equal and nonzero, increment counter
    if (stream_delta_hist[set][0] == stream_delta_hist[set][1] &&
        stream_delta_hist[set][0] != 0) {
        if (stream_counter[set] < 3) stream_counter[set]++;
    } else {
        if (stream_counter[set] > 0) stream_counter[set]--;
    }

    // --- DIP policy selection ---
    bool use_lip = false;
    if (is_leader_lip[set])
        use_lip = true;
    else if (is_leader_bip[set])
        use_lip = false;
    else
        use_lip = (PSEL >= 512);

    // --- Decide insertion RRPV ---
    uint8_t ins_rrpv = 2; // Default: SRRIP mid-range

    if (use_lip) {
        ins_rrpv = 3; // LIP: insert at distant, only promote on hit
    } else {
        // BIP: insert at MRU (0) rarely; mostly at distant
        ins_rrpv = ((rand() % 32) == 0) ? 0 : 3;
    }

    // --- Dead-block predictor bias ---
    // If the victim block was recently reused, insert at MRU
    if (deadblock_reuse[set][way] >= 2)
        ins_rrpv = 0;

    // --- Streaming filter: if streaming detected, bypass with 50% probability or insert at distant ---
    if (stream_counter[set] >= 2) {
        if ((rand() % 2) == 0) {
            // Bypass: do not update replacement state for this fill
            return;
        } else {
            ins_rrpv = 3;
        }
    }

    // --- Insert block ---
    rrpv[set][way] = ins_rrpv;
    deadblock_reuse[set][way] = 0;

    // --- On eviction: decay dead-block predictor for victim block (simulate periodic decay) ---
    if ((dbp_access_count % DEADBLOCK_DECAY_INTERVAL) == 0) {
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            for (uint32_t w = 0; w < LLC_WAYS; ++w)
                if (deadblock_reuse[s][w] > 0) deadblock_reuse[s][w]--;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "Dead-Block Predictor + DIP Set-Dueling + Streaming Filter: Final statistics." << std::endl;
    std::cout << "PSEL: " << PSEL << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Optionally print PSEL, dead-block histogram, streaming counter stats
}