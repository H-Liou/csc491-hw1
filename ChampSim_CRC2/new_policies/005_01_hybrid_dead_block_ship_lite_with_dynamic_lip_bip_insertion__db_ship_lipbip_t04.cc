#include <vector>
#include <cstdint>
#include <cstring>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// DIP-style LIP/BIP set dueling
#define LEADER_SETS 64
#define PSEL_BITS 10
#define PSEL_MAX ((1 << PSEL_BITS) - 1)
#define PSEL_INIT (PSEL_MAX / 2)

// SHiP-lite signature table
#define SIG_BITS 5
#define SIG_ENTRIES (1 << SIG_BITS)      // 32 entries
#define SIG_COUNTER_BITS 2
#define SIG_COUNTER_MAX ((1 << SIG_COUNTER_BITS) - 1)
#define SIG_REUSE_THRESHOLD 1

// Dead-block bit
struct BLOCK_META {
    uint8_t dead;                 // 1 bit: 1=dead, 0=live
    uint8_t signature;            // 5 bits
};

std::vector<BLOCK_META> block_meta;

// SHiP-lite signature table: 32 entries × 2 bits
std::vector<uint8_t> sig_table;

// DIP global policy selector
uint16_t psel = PSEL_INIT;

// Leader sets: first 32 for LIP, last 32 for BIP
std::vector<uint8_t> is_lip_leader;
std::vector<uint8_t> is_bip_leader;

// Statistics
uint64_t access_counter = 0;
uint64_t dead_evictions = 0;
uint64_t ship_hits = 0;
uint64_t ship_promotes = 0;
uint64_t lip_inserts = 0;
uint64_t bip_inserts = 0;

// Helper: get block meta index
inline size_t get_block_meta_idx(uint32_t set, uint32_t way) {
    return set * LLC_WAYS + way;
}

// SHiP-lite: extract 5-bit signature from PC
inline uint8_t get_signature(uint64_t PC) {
    return (PC ^ (PC >> 7)) & (SIG_ENTRIES - 1);
}

// Initialization
void InitReplacementState() {
    block_meta.resize(LLC_SETS * LLC_WAYS);
    sig_table.resize(SIG_ENTRIES, SIG_COUNTER_MAX / 2);
    is_lip_leader.resize(LLC_SETS, 0);
    is_bip_leader.resize(LLC_SETS, 0);

    for (size_t i = 0; i < block_meta.size(); i++) {
        block_meta[i].dead = 1; // all blocks start as dead
        block_meta[i].signature = 0;
    }
    // Assign leader sets (first 32 for LIP, last 32 for BIP)
    for (uint32_t i = 0; i < LEADER_SETS / 2; i++) {
        is_lip_leader[i] = 1;
        is_bip_leader[LLC_SETS - 1 - i] = 1;
    }
    access_counter = 0;
    dead_evictions = 0;
    ship_hits = 0;
    ship_promotes = 0;
    lip_inserts = 0;
    bip_inserts = 0;
    psel = PSEL_INIT;
}

// Find victim in the set: prefer dead blocks, else LRU
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // First, look for a dead block
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        size_t idx = get_block_meta_idx(set, way);
        if (block_meta[idx].dead == 1)
            return way;
    }
    // If none, evict LRU (assume way 0 is LRU, way 15 is MRU)
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

    size_t idx = get_block_meta_idx(set, way);
    BLOCK_META &meta = block_meta[idx];

    uint8_t signature = get_signature(PC);

    // On cache hit
    if (hit) {
        // Mark block as live
        meta.dead = 0;
        // SHiP: increment signature reuse counter (max saturate)
        if (sig_table[meta.signature] < SIG_COUNTER_MAX)
            sig_table[meta.signature]++;
        ship_hits++;
        ship_promotes++;
        return;
    }

    // On miss: insertion
    meta.signature = signature;

    // DIP set dueling: choose LIP or BIP
    uint8_t use_lip = 0, use_bip = 0;
    if (is_lip_leader[set]) use_lip = 1;
    if (is_bip_leader[set]) use_bip = 1;

    uint8_t insert_at_mru = 0;
    static uint32_t bip_ctr = 0;

    if (use_bip || (!use_lip && !use_bip && psel < (PSEL_MAX / 2))) {
        // BIP: insert at MRU every 1/32 fills, else at LRU
        bip_ctr++;
        if ((bip_ctr & 0x1F) == 0)
            insert_at_mru = 1;
        bip_inserts++;
    } else if (use_lip || (!use_lip && !use_bip && psel >= (PSEL_MAX / 2))) {
        // LIP: always insert at LRU
        insert_at_mru = 0;
        lip_inserts++;
    }

    // SHiP-lite: if signature shows reuse, insert at MRU
    if (sig_table[signature] > SIG_REUSE_THRESHOLD) {
        insert_at_mru = 1;
        ship_promotes++;
    }

    // Set dead bit: block is dead until proven live
    meta.dead = 1;

    // On fill: move to MRU or LRU
    // (Assume way 15 is MRU, way 0 is LRU; move filled block to correct position)
    // If insert_at_mru, swap with way 15; else, leave at way 0
    // For simulation, just note the intention (actual movement handled by cache logic)

    // SHiP: on eviction, decrement signature reuse counter (min 0)
    uint8_t victim_sig = get_signature(PC);
    if (!hit) {
        if (sig_table[victim_sig] > 0)
            sig_table[victim_sig]--;
    }

    // Update PSEL for leader sets
    if (use_lip) {
        if (hit && psel < PSEL_MAX) psel++;
    }
    if (use_bip) {
        if (hit && psel > 0) psel--;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "DB-SHiP-LIPBIP: Dead-block SHiP-lite DIP stats\n";
    std::cout << "Total accesses: " << access_counter << "\n";
    std::cout << "Dead block evictions: " << dead_evictions << "\n";
    std::cout << "SHiP hits: " << ship_hits << "\n";
    std::cout << "SHiP MRU promotions: " << ship_promotes << "\n";
    std::cout << "LIP fills: " << lip_inserts << "\n";
    std::cout << "BIP fills: " << bip_inserts << "\n";
    std::cout << "PSEL value: " << psel << "\n";
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    std::cout << "DB-SHiP-LIPBIP heartbeat: accesses=" << access_counter
              << ", ship_hits=" << ship_hits
              << ", ship_promotes=" << ship_promotes
              << ", psel=" << psel << "\n";
}