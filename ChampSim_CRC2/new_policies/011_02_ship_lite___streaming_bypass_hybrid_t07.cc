#include <vector>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// SHiP-lite: 5-bit signature per block, global table (1024 entries) with 2-bit outcome
#define SHIP_SIG_BITS 5
#define SHIP_TABLE_SIZE 1024
std::vector<uint8_t> block_rrpv;           // 2 bits per block: RRPV
std::vector<uint8_t> block_sig;            // 5 bits per block: signature
std::vector<uint8_t> ship_table;           // SHiP table: 2 bits per signature
std::vector<uint8_t> stream_cnt;           // Per-set 2-bit streaming counter
std::vector<uint64_t> last_addr;           // Per-set last accessed block address

// Stats
uint64_t access_counter = 0;
uint64_t hits = 0;
uint64_t ship_mru_inserts = 0;
uint64_t ship_lru_inserts = 0;
uint64_t stream_bypass = 0;

// Helper: get block metadata index
inline size_t get_block_idx(uint32_t set, uint32_t way) {
    return set * LLC_WAYS + way;
}

// Hash PC for SHiP signature
inline uint16_t get_ship_sig(uint64_t PC) {
    // Simple CRC or XOR for 5 bits
    return (PC ^ (PC >> 7) ^ (PC >> 13)) & ((1 << SHIP_SIG_BITS) - 1);
}

// Initialization
void InitReplacementState() {
    block_rrpv.resize(LLC_SETS * LLC_WAYS, 3); // LRU
    block_sig.resize(LLC_SETS * LLC_WAYS, 0);
    ship_table.resize(SHIP_TABLE_SIZE, 1);     // Initial neutral reuse: 1
    stream_cnt.resize(LLC_SETS, 0);
    last_addr.resize(LLC_SETS, 0);

    access_counter = 0;
    hits = 0;
    ship_mru_inserts = 0;
    ship_lru_inserts = 0;
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
    uint16_t sig = get_ship_sig(PC);

    // On hit: promote block to MRU + update SHiP outcome
    if (hit) {
        block_rrpv[idx] = 0;
        hits++;
        // Strengthen signature reuse in SHiP table (max 3)
        if (ship_table[sig] < 3) ship_table[sig]++;
        return;
    }

    // --- Streaming bypass/insertion ---
    if (stream_cnt[set] == 3) {
        // Streaming detected: bypass (do not insert, simulate by setting RRPV=3)
        block_rrpv[idx] = 3;
        block_sig[idx] = sig;
        stream_bypass++;
        return;
    }

    // --- SHiP-based insertion depth ---
    // Use SHiP table to choose insertion position
    if (ship_table[sig] >= 2) {
        // History shows reuse: insert at MRU
        block_rrpv[idx] = 0;
        ship_mru_inserts++;
    } else {
        // History shows dead-on-arrival: insert at LRU
        block_rrpv[idx] = 3;
        ship_lru_inserts++;
    }
    block_sig[idx] = sig;

    // --- On eviction: update SHiP outcome if block was not reused ---
    if (type == 0 /* writeback or replacement */) {
        // If block was not hit since insertion, weaken SHiP reuse
        uint16_t victim_sig = block_sig[idx];
        if (ship_table[victim_sig] > 0) ship_table[victim_sig]--;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "SHiP-lite + Streaming Bypass Hybrid\n";
    std::cout << "Total accesses: " << access_counter << "\n";
    std::cout << "Hits: " << hits << "\n";
    std::cout << "SHiP MRU inserts: " << ship_mru_inserts << "\n";
    std::cout << "SHiP LRU inserts: " << ship_lru_inserts << "\n";
    std::cout << "Streaming bypasses: " << stream_bypass << "\n";
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    std::cout << "SHiP+Streaming heartbeat: accesses=" << access_counter
              << ", hits=" << hits
              << ", ship_mru=" << ship_mru_inserts
              << ", ship_lru=" << ship_lru_inserts
              << ", stream_bypass=" << stream_bypass
              << "\n";
}