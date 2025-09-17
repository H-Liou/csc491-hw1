#include <vector>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// SHiP-lite: per-set, 64-entry table, 6-bit signature, 2-bit counter
#define SHIP_SIG_BITS 6
#define SHIP_TABLE_ENTRIES 64
struct SHIPEntry {
    uint8_t counter; // 2 bits
    uint16_t signature; // 6 bits
};
std::vector<std::vector<SHIPEntry>> ship_table;

// Per-block metadata: 2-bit RRPV, 6-bit signature
std::vector<uint8_t> block_rrpv;
std::vector<uint8_t> block_sig;

// Streaming detector: per-set 2-bit saturating counter
std::vector<uint8_t> stream_cnt;
std::vector<uint64_t> last_addr;

// Stats
uint64_t access_counter = 0;
uint64_t hits = 0;
uint64_t ship_mru_inserts = 0;
uint64_t ship_dist_inserts = 0;
uint64_t stream_bypass = 0;

// Helper: get block meta index
inline size_t get_block_idx(uint32_t set, uint32_t way) {
    return set * LLC_WAYS + way;
}

// Helper: get SHiP table index
inline size_t get_ship_idx(uint32_t set, uint16_t sig) {
    return sig % SHIP_TABLE_ENTRIES;
}

// Initialization
void InitReplacementState() {
    block_rrpv.resize(LLC_SETS * LLC_WAYS, 3); // LRU
    block_sig.resize(LLC_SETS * LLC_WAYS, 0);
    ship_table.resize(LLC_SETS);
    for (size_t s = 0; s < LLC_SETS; s++) {
        ship_table[s].resize(SHIP_TABLE_ENTRIES);
        for (size_t e = 0; e < SHIP_TABLE_ENTRIES; e++) {
            ship_table[s][e].counter = 1; // neutral
            ship_table[s][e].signature = 0;
        }
    }
    stream_cnt.resize(LLC_SETS, 0);
    last_addr.resize(LLC_SETS, 0);

    access_counter = 0;
    hits = 0;
    ship_mru_inserts = 0;
    ship_dist_inserts = 0;
    stream_bypass = 0;
}

// Victim selection: standard RRIP
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Find block with RRPV==3
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        size_t idx = get_block_idx(set, way);
        if (block_rrpv[idx] == 3)
            return way;
    }
    // If none, increment RRPVs and retry
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        size_t idx = get_block_idx(set, way);
        if (block_rrpv[idx] < 3)
            block_rrpv[idx]++;
    }
    // Second pass
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        size_t idx = get_block_idx(set, way);
        if (block_rrpv[idx] == 3)
            return way;
    }
    // If still none, pick way 0
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
    access_counter++;

    // --- Streaming detector ---
    uint64_t addr = paddr >> 6; // block address
    uint64_t delta = (last_addr[set] == 0) ? 0 : (addr > last_addr[set] ? addr - last_addr[set] : last_addr[set] - addr);
    if (last_addr[set] != 0) {
        if (delta == 1 || delta == 0) {
            if (stream_cnt[set] < 3) stream_cnt[set]++;
        } else {
            if (stream_cnt[set] > 0) stream_cnt[set]--;
        }
    }
    last_addr[set] = addr;

    size_t idx = get_block_idx(set, way);

    // Compute SHiP signature (6 bits): lower bits of PC
    uint16_t sig = (PC ^ (PC >> 6)) & ((1 << SHIP_SIG_BITS) - 1);
    block_sig[idx] = sig;

    // --- On hit: promote block to MRU, update SHiP ---
    if (hit) {
        block_rrpv[idx] = 0;
        hits++;
        // Update SHiP counter (increase confidence)
        size_t ship_idx = get_ship_idx(set, sig);
        if (ship_table[set][ship_idx].counter < 3)
            ship_table[set][ship_idx].counter++;
        ship_table[set][ship_idx].signature = sig;
        return;
    }

    // --- Streaming bypass/insertion ---
    if (stream_cnt[set] == 3) {
        // Streaming detected: insert at RRPV=3 (bypass)
        block_rrpv[idx] = 3;
        stream_bypass++;
        // Update SHiP counter (decrease confidence)
        size_t ship_idx = get_ship_idx(set, sig);
        if (ship_table[set][ship_idx].counter > 0)
            ship_table[set][ship_idx].counter--;
        ship_table[set][ship_idx].signature = sig;
        return;
    }

    // --- SHiP-lite insertion ---
    size_t ship_idx = get_ship_idx(set, sig);
    uint8_t ship_conf = ship_table[set][ship_idx].counter;
    ship_table[set][ship_idx].signature = sig;

    if (ship_conf >= 2) {
        // High reuse history: insert at MRU (RRPV=0)
        block_rrpv[idx] = 0;
        ship_mru_inserts++;
    } else {
        // Low reuse: insert at distant (RRPV=2)
        block_rrpv[idx] = 2;
        ship_dist_inserts++;
    }

    // On eviction: penalize SHiP if block was not reused
    // (simulate dead-block detection: if block evicted at RRPV==3 and not hit)
    // This can be handled outside if needed, but here we do not track dead-blocks explicitly.

}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "SHiP-Lite + Streaming Bypass Hybrid\n";
    std::cout << "Total accesses: " << access_counter << "\n";
    std::cout << "Hits: " << hits << "\n";
    std::cout << "SHiP MRU inserts: " << ship_mru_inserts << "\n";
    std::cout << "SHiP distant inserts: " << ship_dist_inserts << "\n";
    std::cout << "Streaming bypasses: " << stream_bypass << "\n";
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    std::cout << "SHiP+Streaming heartbeat: accesses=" << access_counter
              << ", hits=" << hits
              << ", ship_mru=" << ship_mru_inserts
              << ", ship_dist=" << ship_dist_inserts
              << ", stream_bypass=" << stream_bypass
              << "\n";
}