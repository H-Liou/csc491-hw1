#include <vector>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// DIP: 64 leader sets, 10-bit PSEL
#define DIP_LEADER_SETS 64
#define DIP_PSEL_BITS 10
#define DIP_PSEL_MAX ((1 << DIP_PSEL_BITS) - 1)
#define DIP_BIP_PROB 32 // Insert at MRU 1/32 times in BIP

// Per-block metadata: 2-bit RRPV, 2-bit dead-block counter
std::vector<uint8_t> block_rrpv;
std::vector<uint8_t> block_dead;

// DIP: leader set indices and PSEL
std::vector<bool> is_lip_leader;
std::vector<bool> is_bip_leader;
uint16_t dip_psel = DIP_PSEL_MAX / 2;

// Stats
uint64_t access_counter = 0;
uint64_t hits = 0;
uint64_t lip_inserts = 0;
uint64_t bip_inserts = 0;
uint64_t dead_evictions = 0;

// Helper: get block meta index
inline size_t get_block_idx(uint32_t set, uint32_t way) {
    return set * LLC_WAYS + way;
}

// Initialization
void InitReplacementState() {
    block_rrpv.resize(LLC_SETS * LLC_WAYS, 3); // LRU
    block_dead.resize(LLC_SETS * LLC_WAYS, 0);

    is_lip_leader.resize(LLC_SETS, false);
    is_bip_leader.resize(LLC_SETS, false);

    // Assign leader sets: first 32 as LIP, next 32 as BIP
    for (uint32_t i = 0; i < DIP_LEADER_SETS; i++) {
        if (i < DIP_LEADER_SETS / 2)
            is_lip_leader[i] = true;
        else
            is_bip_leader[i] = true;
    }
    dip_psel = DIP_PSEL_MAX / 2;

    access_counter = 0;
    hits = 0;
    lip_inserts = 0;
    bip_inserts = 0;
    dead_evictions = 0;
}

// Find victim in the set: prefer blocks with dead-block counter==3, else RRIP
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // First, look for block with dead-block counter==3
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        size_t idx = get_block_idx(set, way);
        if (block_dead[idx] == 3)
            return way;
    }
    // Next, standard RRIP: look for RRPV==3
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

    size_t idx = get_block_idx(set, way);

    // On hit: promote block to MRU, reset dead-block counter
    if (hit) {
        block_rrpv[idx] = 0;
        block_dead[idx] = 0;
        hits++;
        return;
    }

    // --- DIP insertion policy ---
    bool lip_leader = (set < DIP_LEADER_SETS) && is_lip_leader[set];
    bool bip_leader = (set < DIP_LEADER_SETS) && is_bip_leader[set];
    bool use_lip = false;

    if (lip_leader)
        use_lip = true;
    else if (bip_leader)
        use_lip = false;
    else
        use_lip = (dip_psel >= (DIP_PSEL_MAX / 2));

    // LIP: always insert at LRU (RRPV=3)
    // BIP: insert at MRU (RRPV=0) 1/32 times, else at LRU (RRPV=3)
    if (use_lip) {
        block_rrpv[idx] = 3;
        lip_inserts++;
    } else {
        if ((access_counter & (DIP_BIP_PROB - 1)) == 0) {
            block_rrpv[idx] = 0;
        } else {
            block_rrpv[idx] = 3;
        }
        bip_inserts++;
    }
    block_dead[idx] = 0; // reset on insertion

    // On eviction: increment dead-block counter
    if (victim_addr != 0) {
        // Find victim block in set
        for (uint32_t vway = 0; vway < LLC_WAYS; vway++) {
            size_t vidx = get_block_idx(set, vway);
            if (current_set[vway].address == victim_addr) {
                if (block_dead[vidx] < 3) block_dead[vidx]++;
                if (block_dead[vidx] == 3) dead_evictions++;
                break;
            }
        }
        // Update DIP PSEL for leader sets
        if (set < DIP_LEADER_SETS) {
            if (is_lip_leader[set]) {
                // If hit, increment PSEL; else decrement
                if (hit && dip_psel < DIP_PSEL_MAX) dip_psel++;
                else if (!hit && dip_psel > 0) dip_psel--;
            } else if (is_bip_leader[set]) {
                if (hit && dip_psel > 0) dip_psel--;
                else if (!hit && dip_psel < DIP_PSEL_MAX) dip_psel++;
            }
        }
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "DIP-LIP/BIP + Dead-Block Counter Hybrid\n";
    std::cout << "Total accesses: " << access_counter << "\n";
    std::cout << "Hits: " << hits << "\n";
    std::cout << "LIP inserts: " << lip_inserts << "\n";
    std::cout << "BIP inserts: " << bip_inserts << "\n";
    std::cout << "Dead-block evictions: " << dead_evictions << "\n";
    std::cout << "DIP PSEL: " << dip_psel << "\n";
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    std::cout << "DIP+Dead heartbeat: accesses=" << access_counter
              << ", hits=" << hits
              << ", lip=" << lip_inserts
              << ", bip=" << bip_inserts
              << ", dead_evictions=" << dead_evictions
              << ", psel=" << dip_psel << "\n";
}