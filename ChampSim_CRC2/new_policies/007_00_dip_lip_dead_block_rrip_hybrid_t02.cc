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

// Per-block metadata: RRPV + dead-block counter (2 bits)
struct BLOCK_META {
    uint8_t rrpv;      // 2 bits
    uint8_t dead_cnt;  // 2 bits
};
std::vector<BLOCK_META> block_meta;

// Stats
uint64_t access_counter = 0;
uint64_t lip_inserts = 0;
uint64_t bip_inserts = 0;
uint64_t dead_inserts = 0;
uint64_t hits = 0;
uint64_t dead_evictions = 0;
uint64_t decay_events = 0;

// Helper: get block meta index
inline size_t get_block_meta_idx(uint32_t set, uint32_t way) {
    return set * LLC_WAYS + way;
}

// Initialization
void InitReplacementState() {
    block_meta.resize(LLC_SETS * LLC_WAYS);
    leader_set_type.resize(NUM_LEADER_SETS);

    // Assign leader sets: evenly spaced
    for (size_t i = 0; i < NUM_LEADER_SETS; i++) {
        leader_set_type[i] = (i < NUM_LEADER_SETS / 2) ? 0 : 1; // 0:LIP, 1:BIP
    }

    for (size_t i = 0; i < block_meta.size(); i++) {
        block_meta[i].rrpv = 3; // LRU
        block_meta[i].dead_cnt = 1; // neutral
    }

    access_counter = 0;
    lip_inserts = 0;
    bip_inserts = 0;
    dead_inserts = 0;
    hits = 0;
    dead_evictions = 0;
    decay_events = 0;
}

// Victim selection: Prefer blocks with dead_cnt==0 and RRPV==3
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // First, try to find a block with dead_cnt==0 and RRPV==3
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        size_t idx = get_block_meta_idx(set, way);
        if (block_meta[idx].rrpv == 3 && block_meta[idx].dead_cnt == 0)
            return way;
    }
    // Next, any block with RRPV==3
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
    // Second pass: dead_cnt==0 and RRPV==3
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        size_t idx = get_block_meta_idx(set, way);
        if (block_meta[idx].rrpv == 3 && block_meta[idx].dead_cnt == 0)
            return way;
    }
    // Any block with RRPV==3
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

    // Periodic decay of dead_cnt for all blocks every 4096 accesses
    if ((access_counter & 0xFFF) == 0) {
        for (size_t i = 0; i < block_meta.size(); i++) {
            if (block_meta[i].dead_cnt > 0)
                block_meta[i].dead_cnt--;
        }
        decay_events++;
    }

    // On hit: promote block to MRU, increment dead_cnt (max saturate)
    if (hit) {
        meta.rrpv = 0;
        if (meta.dead_cnt < 3)
            meta.dead_cnt++;
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

    // Dead-block prediction: if dead_cnt==0, insert at LRU (RRPV=3)
    if (meta.dead_cnt == 0) {
        meta.rrpv = 3;
        dead_inserts++;
    } else {
        // DIP: LIP inserts at LRU (RRPV=3), BIP inserts at MRU (RRPV=0) with 1/32 probability, else LRU
        if (use_bip) {
            if ((access_counter & 0x1F) == 0) // 1/32
                meta.rrpv = 0;
            else
                meta.rrpv = 3;
            bip_inserts++;
        } else {
            meta.rrpv = 3;
            lip_inserts++;
        }
    }
    meta.dead_cnt = 1; // neutral on fill

    // On victim: update dead-block stats
    size_t victim_idx = get_block_meta_idx(set, way);
    if (block_meta[victim_idx].dead_cnt == 0)
        dead_evictions++;

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
    std::cout << "DIP-LIP Dead-Block RRIP Hybrid\n";
    std::cout << "Total accesses: " << access_counter << "\n";
    std::cout << "Hits: " << hits << "\n";
    std::cout << "LIP inserts: " << lip_inserts << "\n";
    std::cout << "BIP inserts: " << bip_inserts << "\n";
    std::cout << "Dead-block inserts: " << dead_inserts << "\n";
    std::cout << "Dead-block evictions: " << dead_evictions << "\n";
    std::cout << "Decay events: " << decay_events << "\n";
    std::cout << "PSEL value: " << psel << "\n";
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    std::cout << "DIP-LIP Dead-Block heartbeat: accesses=" << access_counter
              << ", hits=" << hits
              << ", lip_inserts=" << lip_inserts
              << ", bip_inserts=" << bip_inserts
              << ", dead_inserts=" << dead_inserts
              << ", dead_evictions=" << dead_evictions
              << ", decay_events=" << decay_events
              << ", PSEL=" << psel << "\n";
}