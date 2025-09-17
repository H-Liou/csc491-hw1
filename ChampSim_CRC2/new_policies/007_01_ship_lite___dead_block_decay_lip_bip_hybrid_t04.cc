#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// SHiP-lite: 6-bit signature, 2-bit outcome counter
#define SHIP_SIG_BITS 6
#define SHIP_SIG_ENTRIES 1024 // 1K entries: 6b index, 2b counter = 256B
struct SHIP_SIG_ENTRY {
    uint8_t counter; // 2 bits
};
std::vector<SHIP_SIG_ENTRY> ship_sig_table;

// Per-block: signature + RRPV + dead-block counter
struct BLOCK_META {
    uint8_t rrpv;      // 2 bits
    uint8_t sig;       // 6 bits
    uint8_t deadctr;   // 2 bits
};
std::vector<BLOCK_META> block_meta;

// DIP-style set-dueling: LIP/BIP
#define PSEL_BITS 10
uint16_t psel = (1 << (PSEL_BITS - 1)); // 10-bit PSEL
#define NUM_LEADER_SETS 32
std::vector<uint8_t> leader_set_type; // 0: LIP, 1: BIP

// Dead-block decay
#define DEADBLOCK_DECAY_INTERVAL 4096
uint64_t access_counter = 0;

// Stats
uint64_t ship_hits = 0;
uint64_t ship_promotes = 0;
uint64_t lip_inserts = 0;
uint64_t bip_inserts = 0;
uint64_t deadblock_inserts = 0;
uint64_t deadblock_hits = 0;

// Helper: get block meta index
inline size_t get_block_meta_idx(uint32_t set, uint32_t way) {
    return set * LLC_WAYS + way;
}

// Helper: get SHiP signature index
inline uint32_t get_ship_sig_idx(uint64_t PC) {
    return (PC ^ (PC >> 6)) & (SHIP_SIG_ENTRIES - 1);
}

// Initialization
void InitReplacementState() {
    block_meta.resize(LLC_SETS * LLC_WAYS);
    ship_sig_table.resize(SHIP_SIG_ENTRIES);
    leader_set_type.resize(NUM_LEADER_SETS);

    // Assign leader sets: evenly spaced
    for (size_t i = 0; i < NUM_LEADER_SETS; i++) {
        leader_set_type[i] = (i < NUM_LEADER_SETS / 2) ? 0 : 1; // 0:LIP, 1:BIP
    }

    for (size_t i = 0; i < block_meta.size(); i++) {
        block_meta[i].rrpv = 3; // LRU
        block_meta[i].sig = 0;
        block_meta[i].deadctr = 1; // neutral
    }
    for (size_t i = 0; i < ship_sig_table.size(); i++) {
        ship_sig_table[i].counter = 1; // neutral
    }
    access_counter = 0;
    ship_hits = 0;
    ship_promotes = 0;
    lip_inserts = 0;
    bip_inserts = 0;
    deadblock_inserts = 0;
    deadblock_hits = 0;
}

// Victim selection: RRIP
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Prefer blocks with RRPV=3 (LRU)
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

    // SHiP signature
    uint32_t sig_idx = get_ship_sig_idx(PC);

    // Dead-block decay: every DEADBLOCK_DECAY_INTERVAL accesses, decay all deadctr by 1 (if >0)
    if ((access_counter & (DEADBLOCK_DECAY_INTERVAL - 1)) == 0) {
        for (size_t i = 0; i < block_meta.size(); i++) {
            if (block_meta[i].deadctr > 0)
                block_meta[i].deadctr--;
        }
    }

    // On cache hit
    if (hit) {
        // Promote block to MRU
        meta.rrpv = 0;
        // SHiP: increment outcome counter (max saturate)
        if (ship_sig_table[sig_idx].counter < 3)
            ship_sig_table[sig_idx].counter++;
        // Dead-block: increment reuse counter (max 3)
        if (meta.deadctr < 3)
            meta.deadctr++;
        ship_hits++;
        ship_promotes++;
        if (meta.deadctr == 3)
            deadblock_hits++;
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

    // SHiP insertion depth
    uint8_t ship_cnt = ship_sig_table[sig_idx].counter;
    uint8_t ins_rrpv = 2; // default: mid-depth
    if (ship_cnt >= 2) {
        ins_rrpv = 0; // hot PC: insert at MRU
    } else if (ship_cnt == 0) {
        ins_rrpv = 3; // cold PC: insert at LRU
    } // else ins_rrpv = 2;

    // Dead-block approximation: if block's deadctr == 0 (likely dead), insert at LRU
    if (meta.deadctr == 0) {
        ins_rrpv = 3;
        deadblock_inserts++;
    }

    // DIP: BIP inserts at MRU with 1/32 probability, otherwise LRU
    if (use_bip) {
        if ((access_counter & 0x1F) == 0)
            ins_rrpv = 0;
        else
            ins_rrpv = 3;
        bip_inserts++;
    } else {
        lip_inserts++;
    }

    meta.rrpv = ins_rrpv;
    meta.sig = (uint8_t)(sig_idx & ((1 << SHIP_SIG_BITS) - 1));
    // On insertion, reset deadctr to 1 (neutral)
    meta.deadctr = 1;

    // On victim: update SHiP outcome counter
    if (!hit) {
        size_t victim_idx = get_block_meta_idx(set, way);
        uint8_t victim_sig = block_meta[victim_idx].sig;
        if (victim_sig < SHIP_SIG_ENTRIES) {
            // If block was not reused (RRPV==3), decrement outcome counter
            if (block_meta[victim_idx].rrpv == 3) {
                if (ship_sig_table[victim_sig].counter > 0)
                    ship_sig_table[victim_sig].counter--;
            }
        }
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
    std::cout << "SHiP-Lite + Dead-Block Decay LIP/BIP Hybrid\n";
    std::cout << "Total accesses: " << access_counter << "\n";
    std::cout << "SHiP hits: " << ship_hits << "\n";
    std::cout << "SHiP MRU promotions: " << ship_promotes << "\n";
    std::cout << "LIP inserts: " << lip_inserts << "\n";
    std::cout << "BIP inserts: " << bip_inserts << "\n";
    std::cout << "Dead-block LRU inserts: " << deadblock_inserts << "\n";
    std::cout << "Dead-block full hits: " << deadblock_hits << "\n";
    std::cout << "PSEL value: " << psel << "\n";
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    std::cout << "SHiP-Lite+DeadBlock LIP/BIP heartbeat: accesses=" << access_counter
              << ", ship_hits=" << ship_hits
              << ", ship_promotes=" << ship_promotes
              << ", lip_inserts=" << lip_inserts
              << ", bip_inserts=" << bip_inserts
              << ", deadblock_inserts=" << deadblock_inserts
              << ", deadblock_hits=" << deadblock_hits
              << ", PSEL=" << psel << "\n";
}