#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// DIP set-dueling: 32 leader sets, 10-bit PSEL
#define NUM_LEADER_SETS 32
#define PSEL_BITS 10
uint16_t psel = (1 << (PSEL_BITS - 1));
std::vector<uint8_t> leader_set_type; // 0:LIP, 1:BIP

// Per-block metadata: 2-bit RRPV, 2-bit dead-block counter
struct BLOCK_META {
    uint8_t rrpv; // 2 bits
    uint8_t dead_cnt; // 2 bits
};
std::vector<BLOCK_META> block_meta;

// SHiP-lite: 1024-entry signature table, 6-bit signatures, 2-bit outcome counters
#define SHIP_SIG_BITS 6
#define SHIP_TABLE_SIZE 1024
struct SHIP_ENTRY {
    uint8_t counter; // 2 bits
};
std::vector<SHIP_ENTRY> ship_table;

// Stats
uint64_t access_counter = 0;
uint64_t ship_mru_inserts = 0;
uint64_t ship_lru_inserts = 0;
uint64_t hits = 0;
uint64_t lip_inserts = 0;
uint64_t bip_inserts = 0;
uint64_t dead_evictions = 0;

// Helper: get block meta index
inline size_t get_block_meta_idx(uint32_t set, uint32_t way) {
    return set * LLC_WAYS + way;
}

// Helper: SHiP signature (6 bits from PC)
inline uint16_t get_ship_sig(uint64_t PC) {
    return (PC ^ (PC >> 6)) & ((1 << SHIP_SIG_BITS) - 1);
}

// Helper: SHiP table index
inline size_t get_ship_idx(uint16_t sig) {
    return sig % SHIP_TABLE_SIZE;
}

// Initialization
void InitReplacementState() {
    block_meta.resize(LLC_SETS * LLC_WAYS);
    leader_set_type.resize(NUM_LEADER_SETS);
    ship_table.resize(SHIP_TABLE_SIZE);

    // Assign leader sets: evenly spaced
    for (size_t i = 0; i < NUM_LEADER_SETS; i++) {
        leader_set_type[i] = (i < NUM_LEADER_SETS / 2) ? 0 : 1; // 0:LIP, 1:BIP
    }

    for (size_t i = 0; i < block_meta.size(); i++) {
        block_meta[i].rrpv = 3; // LRU
        block_meta[i].dead_cnt = 0;
    }
    for (size_t i = 0; i < ship_table.size(); i++) {
        ship_table[i].counter = 1; // neutral
    }

    access_counter = 0;
    ship_mru_inserts = 0;
    ship_lru_inserts = 0;
    hits = 0;
    lip_inserts = 0;
    bip_inserts = 0;
    dead_evictions = 0;
}

// Victim selection: prefer blocks with dead_cnt==3, else RRIP
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // First, try to find a block with dead_cnt==3 (dead block)
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        size_t idx = get_block_meta_idx(set, way);
        if (block_meta[idx].dead_cnt == 3)
            return way;
    }
    // Next, standard RRIP: find block with RRPV==3
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        size_t idx = get_block_meta_idx(set, way);
        if (block_meta[idx].rrpv == 3)
            return way;
    }
    // If none, increment RRPVs and retry
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        size_t idx = get_block_meta_idx(set, way);
        if (block_meta[idx].rrpv < 3)
            block_meta[idx].rrpv++;
    }
    // Second pass
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        size_t idx = get_block_meta_idx(set, way);
        if (block_meta[idx].rrpv == 3)
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

    size_t idx = get_block_meta_idx(set, way);
    BLOCK_META &meta = block_meta[idx];

    // --- Dead-block decay: every 4096 accesses, decay all dead_cnt by 1 (if >0)
    if ((access_counter & 0xFFF) == 0) {
        for (size_t i = 0; i < block_meta.size(); i++) {
            if (block_meta[i].dead_cnt > 0)
                block_meta[i].dead_cnt--;
        }
    }

    // --- SHiP-lite update ---
    uint16_t sig = get_ship_sig(PC);
    size_t ship_idx = get_ship_idx(sig);
    SHIP_ENTRY &ship_entry = ship_table[ship_idx];

    // On hit: promote block to MRU, increment SHiP counter (max saturate), reset dead_cnt
    if (hit) {
        meta.rrpv = 0;
        if (ship_entry.counter < 3) ship_entry.counter++;
        meta.dead_cnt = 0;
        hits++;
        return;
    }

    // On miss: insertion
    // DIP set-dueling: leader sets use fixed policy, others use PSEL
    bool is_leader = (set % (LLC_SETS / NUM_LEADER_SETS)) == 0;
    uint8_t leader_type = 0;
    if (is_leader) {
        leader_type = leader_set_type[set / (LLC_SETS / NUM_LEADER_SETS)];
    }
    bool use_bip = false;
    if (is_leader) {
        use_bip = (leader_type == 1);
    } else {
        use_bip = (psel < (1 << (PSEL_BITS - 1)));
    }

    // --- SHiP-lite insertion control ---
    if (ship_entry.counter >= 2) {
        // High reuse signature: insert at MRU
        meta.rrpv = 0;
        ship_mru_inserts++;
    } else {
        // Low reuse signature: insert at LRU
        meta.rrpv = 3;
        ship_lru_inserts++;
    }

    // DIP: adjust insertion for non-SHiP blocks (if signature neutral)
    if (ship_entry.counter == 1) {
        if (use_bip) {
            // BIP: insert at MRU with 1/32 probability, else LRU
            if ((access_counter & 0x1F) == 0)
                meta.rrpv = 0;
            else
                meta.rrpv = 3;
            bip_inserts++;
        } else {
            // LIP: always insert at LRU
            meta.rrpv = 3;
            lip_inserts++;
        }
    }

    // On victim: update SHiP counter (if not high-reuse), increment dead_cnt of victim
    if (way < LLC_WAYS) {
        size_t victim_idx = get_block_meta_idx(set, way);
        BLOCK_META &victim_meta = block_meta[victim_idx];
        if (victim_meta.dead_cnt < 3)
            victim_meta.dead_cnt++;
        if (victim_meta.dead_cnt == 3)
            dead_evictions++;
        // Decrement SHiP counter for victim signature
        uint16_t victim_sig = get_ship_sig(PC);
        size_t victim_ship_idx = get_ship_idx(victim_sig);
        SHIP_ENTRY &victim_entry = ship_table[victim_ship_idx];
        if (victim_entry.counter > 0) victim_entry.counter--;
    }

    // DIP PSEL update: only for leader sets
    if (is_leader && !hit) {
        if (leader_type == 0) { // LIP leader
            if (psel < ((1 << PSEL_BITS) - 1)) psel++;
        } else { // BIP leader
            if (psel > 0) psel--;
        }
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "SHiP-Lite + Dead-Block Decay DIP Hybrid\n";
    std::cout << "Total accesses: " << access_counter << "\n";
    std::cout << "Hits: " << hits << "\n";
    std::cout << "SHiP MRU inserts: " << ship_mru_inserts << "\n";
    std::cout << "SHiP LRU inserts: " << ship_lru_inserts << "\n";
    std::cout << "LIP inserts: " << lip_inserts << "\n";
    std::cout << "BIP inserts: " << bip_inserts << "\n";
    std::cout << "Dead-block evictions: " << dead_evictions << "\n";
    std::cout << "PSEL value: " << psel << "\n";
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    std::cout << "SHiP-Lite+DeadBlock heartbeat: accesses=" << access_counter
              << ", hits=" << hits
              << ", ship_mru=" << ship_mru_inserts
              << ", ship_lru=" << ship_lru_inserts
              << ", lip=" << lip_inserts
              << ", bip=" << bip_inserts
              << ", dead_evictions=" << dead_evictions
              << ", PSEL=" << psel << "\n";
}