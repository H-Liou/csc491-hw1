#include <vector>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// SHiP-lite: 4096-entry table, 2 bits per entry (PC signature)
#define SHIP_SIG_BITS 6
#define SHIP_TABLE_SIZE (1 << SHIP_SIG_BITS) // 64
#define SHIP_TABLE_ENTRIES (LLC_SETS)        // 2048
#define SHIP_TOTAL_ENTRIES (SHIP_TABLE_ENTRIES) // 2048
#define SHIP_COUNTER_BITS 2

// Per-block metadata: 2-bit RRPV, 6-bit PC signature
std::vector<uint8_t> block_rrpv;
std::vector<uint8_t> block_sig;

// SHiP-lite table: 2048 entries × 2 bits
std::vector<uint8_t> ship_table;

// Streaming detector: per-set 2-bit saturating counter, last address
std::vector<uint8_t> stream_cnt;
std::vector<uint64_t> last_addr;

// Stats
uint64_t access_counter = 0;
uint64_t hits = 0;
uint64_t ship_mru_inserts = 0;
uint64_t ship_lru_inserts = 0;
uint64_t stream_bypass = 0;

// Helper: get block meta index
inline size_t get_block_idx(uint32_t set, uint32_t way) {
    return set * LLC_WAYS + way;
}

// Helper: get SHiP-lite table index (set + PC signature)
inline size_t get_ship_idx(uint32_t set, uint64_t PC) {
    uint64_t sig = (PC >> 2) & (SHIP_TABLE_SIZE - 1); // 6-bit signature
    return ((set << SHIP_SIG_BITS) | sig) % SHIP_TOTAL_ENTRIES;
}

// Initialization
void InitReplacementState() {
    block_rrpv.resize(LLC_SETS * LLC_WAYS, 3); // LRU
    block_sig.resize(LLC_SETS * LLC_WAYS, 0);
    ship_table.resize(SHIP_TOTAL_ENTRIES, 1); // Start neutral
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
    size_t ship_idx = get_ship_idx(set, PC);

    // On hit: promote block to MRU, update SHiP outcome
    if (hit) {
        block_rrpv[idx] = 0;
        hits++;
        // Update SHiP counter (max 3)
        if (ship_table[ship_idx] < 3) ship_table[ship_idx]++;
        return;
    }

    // --- Streaming bypass/insertion ---
    if (stream_cnt[set] == 3) {
        // Streaming detected: bypass by inserting at RRPV=3 (distant LRU)
        block_rrpv[idx] = 3;
        block_sig[idx] = (PC >> 2) & (SHIP_TABLE_SIZE - 1);
        stream_bypass++;
        return;
    }

    // --- SHiP-lite insertion ---
    uint8_t ship_ctr = ship_table[ship_idx];
    block_sig[idx] = (PC >> 2) & (SHIP_TABLE_SIZE - 1);

    if (ship_ctr >= 2) {
        // High reuse: insert at MRU (RRPV=0)
        block_rrpv[idx] = 0;
        ship_mru_inserts++;
    } else {
        // Low reuse: insert at distant RRPV (RRPV=2)
        block_rrpv[idx] = 2;
        ship_lru_inserts++;
    }

    // On eviction: update SHiP outcome (dead block)
    if (victim_addr != 0) {
        size_t victim_ship_idx = get_ship_idx(set, victim_addr);
        // If block was not reused, decrement counter
        if (ship_table[victim_ship_idx] > 0) ship_table[victim_ship_idx]--;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "SHiP-Lite + Streaming Bypass Hybrid\n";
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
              << ", stream_bypass=" << stream_bypass << "\n";
}