#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- RRIP metadata ---
uint8_t rrpv[LLC_SETS][LLC_WAYS]; // 2 bits/line

// --- SHiP-lite: 2048-entry signature table, each entry: 6-bit PC signature + 2-bit reuse counter ---
#define SHIP_SIG_BITS 6
#define SHIP_TABLE_SIZE 2048
struct SHIPEntry {
    uint8_t valid;          // 1 bit
    uint8_t signature;      // 6 bits
    uint8_t reuse;          // 2 bits
};
SHIPEntry ship_table[SHIP_TABLE_SIZE];

// --- Per-line PC signature tracking ---
uint8_t line_sig[LLC_SETS][LLC_WAYS]; // 6 bits/line

// --- Streaming detector: per-set 1-bit flag, 32-bit last address ---
uint8_t streaming_flag[LLC_SETS];
uint32_t last_addr[LLC_SETS];

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv)); // Initialize to LRU
    memset(ship_table, 0, sizeof(ship_table));
    memset(line_sig, 0, sizeof(line_sig));
    memset(streaming_flag, 0, sizeof(streaming_flag));
    memset(last_addr, 0, sizeof(last_addr));
}

// --- Victim selection: standard RRIP ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Streaming phase: always evict LRU
    if (streaming_flag[set]) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        // Increment RRPVs if no LRU found
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] < 3)
                rrpv[set][way]++;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
    }

    // Normal RRIP victim selection
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] < 3)
                rrpv[set][way]++;
    }
}

// --- Replacement state update ---
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
    // --- Streaming detector update (per set) ---
    uint32_t block_addr = (uint32_t)(paddr >> 6); // block address
    uint32_t delta = block_addr - last_addr[set];
    if (last_addr[set] != 0 && (delta == 1 || delta == (uint32_t)-1)) {
        streaming_flag[set] = 1; // monotonic access detected
    } else if (last_addr[set] != 0 && delta != 0) {
        streaming_flag[set] = 0;
    }
    last_addr[set] = block_addr;

    // --- Compute PC signature ---
    uint8_t pc_sig = (uint8_t)(PC ^ (PC >> 6)) & ((1 << SHIP_SIG_BITS) - 1);
    uint32_t sig_idx = pc_sig; // Direct mapping for SHiP table; could hash PC if desired

    // --- SHiP table update on hit/miss ---
    if (ship_table[sig_idx].valid && ship_table[sig_idx].signature == pc_sig) {
        if (hit && ship_table[sig_idx].reuse < 3)
            ship_table[sig_idx].reuse++; // Promote if reused
        else if (!hit && ship_table[sig_idx].reuse > 0)
            ship_table[sig_idx].reuse--; // Demote if not reused
    } else {
        // Install new signature
        ship_table[sig_idx].valid = 1;
        ship_table[sig_idx].signature = pc_sig;
        ship_table[sig_idx].reuse = hit ? 2 : 0;
    }

    // --- Set line signature for future eviction learning ---
    line_sig[set][way] = pc_sig;

    // --- Insertion policy ---
    uint8_t ins_rrpv = 2; // Default: SRRIP insertion (RRPV=2)

    // Streaming: always insert at LRU
    if (streaming_flag[set])
        ins_rrpv = 3;
    else {
        // SHiP-lite: Insert at MRU (RRPV=0) if PC reuse counter is high
        if (ship_table[sig_idx].valid && ship_table[sig_idx].reuse >= 2)
            ins_rrpv = 0;
        else if (ship_table[sig_idx].valid && ship_table[sig_idx].reuse == 1)
            ins_rrpv = 1;
        else
            ins_rrpv = 2; // fallback: conservative
    }

    // --- RRIP update ---
    if (hit)
        rrpv[set][way] = 0; // Promote to MRU
    else
        rrpv[set][way] = ins_rrpv;
}

// --- Stats ---
void PrintStats() {
    int streaming_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (streaming_flag[s]) streaming_sets++;
    std::cout << "SHiP-SA: Streaming sets: " << streaming_sets << " / " << LLC_SETS << std::endl;

    int high_reuse = 0, low_reuse = 0;
    for (uint32_t i = 0; i < SHIP_TABLE_SIZE; ++i)
        if (ship_table[i].valid) {
            if (ship_table[i].reuse >= 2) high_reuse++;
            else if (ship_table[i].reuse == 0) low_reuse++;
        }
    std::cout << "SHiP-SA: High-reuse sigs: " << high_reuse << " / " << SHIP_TABLE_SIZE << std::endl;
    std::cout << "SHiP-SA: Low-reuse sigs: " << low_reuse << " / " << SHIP_TABLE_SIZE << std::endl;
}

void PrintStats_Heartbeat() {
    int streaming_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (streaming_flag[s]) streaming_sets++;
    std::cout << "SHiP-SA: Streaming sets: " << streaming_sets << std::endl;
}