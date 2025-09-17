#include <vector>
#include <cstdint>
#include <iostream>
#include <unordered_map>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// RRIP constants
#define RRIP_BITS 2
#define RRIP_MAX ((1 << RRIP_BITS) - 1)
#define RRIP_LONG 3   // Insert with 3 for streaming/irregular
#define RRIP_SHORT 0  // Insert with 0 for high locality

// Signature table parameters
#define SIGTAB_SIZE 8 // Per-set signature table entries
#define SIG_HIT_THRES 2 // At least 2 hits in window to be considered high locality

struct BlockMeta {
    uint8_t valid;
    uint8_t rrip;
    uint64_t tag;
    uint64_t pc_sig;
};

// Signature entry: tracks hits/misses for a PC signature
struct SigEntry {
    uint64_t pc_sig;
    uint16_t hits;
    uint16_t accesses;
};

struct SetState {
    std::vector<BlockMeta> meta;
    std::vector<SigEntry> sigtab;
};

std::vector<SetState> sets(LLC_SETS);

// --- Initialize replacement state ---
void InitReplacementState() {
    for (auto& set : sets) {
        set.meta.assign(LLC_WAYS, {0, RRIP_MAX, 0, 0});
        set.sigtab.assign(SIGTAB_SIZE, {0, 0, 0});
    }
}

// --- Find victim in the set ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    SetState& s = sets[set];
    // Prefer invalid
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        if (!current_set[way].valid)
            return way;
    }
    // Standard RRIP victim selection: pick block(s) with RRIP_MAX
    for (uint32_t round = 0; round < 2; round++) {
        for (uint32_t way = 0; way < LLC_WAYS; way++) {
            if (s.meta[way].rrip == RRIP_MAX)
                return way;
        }
        // Aging: increment all RRIP values
        for (uint32_t way = 0; way < LLC_WAYS; way++) {
            if (s.meta[way].rrip < RRIP_MAX)
                s.meta[way].rrip++;
        }
    }
    // Fallback: evict LRU (highest RRIP)
    uint32_t victim = 0;
    uint8_t max_rrip = 0;
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        if (s.meta[way].rrip >= max_rrip) {
            max_rrip = s.meta[way].rrip;
            victim = way;
        }
    }
    return victim;
}

// --- Update signature table ---
void UpdateSigTable(SetState& s, uint64_t pc_sig, bool hit) {
    // Search for entry
    int found = -1;
    for (int i = 0; i < SIGTAB_SIZE; i++) {
        if (s.sigtab[i].pc_sig == pc_sig) {
            found = i;
            break;
        }
    }
    if (found >= 0) {
        s.sigtab[found].accesses++;
        if (hit)
            s.sigtab[found].hits++;
    } else {
        // Replace oldest (round-robin or LRU, here simple round-robin)
        static uint32_t rr_ptr = 0;
        s.sigtab[rr_ptr] = {pc_sig, hit ? 1 : 0, 1};
        rr_ptr = (rr_ptr + 1) % SIGTAB_SIZE;
    }
}

// --- Query signature table for locality ---
bool IsHighLocality(SetState& s, uint64_t pc_sig) {
    for (int i = 0; i < SIGTAB_SIZE; i++) {
        if (s.sigtab[i].pc_sig == pc_sig) {
            // If hit rate is high enough in recent accesses, treat as high locality
            if (s.sigtab[i].accesses >= 3 && s.sigtab[i].hits >= SIG_HIT_THRES)
                return true;
        }
    }
    return false;
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
    SetState& s = sets[set];
    uint64_t tag = paddr >> 6;
    uint64_t pc_sig = PC & 0xFFF; // 12-bit signature

    // Update per-set signature table
    UpdateSigTable(s, pc_sig, hit);

    // On hit: promote block (set RRIP to 0)
    if (hit) {
        s.meta[way].rrip = 0;
    } else {
        // On miss/insertion: adapt insertion RRIP based on PC signature locality
        if (IsHighLocality(s, pc_sig)) {
            // High locality: retain longer
            s.meta[way].rrip = RRIP_SHORT;
        } else {
            // Streaming/irregular: evict quickly
            s.meta[way].rrip = RRIP_LONG;
        }
    }
    s.meta[way].valid = 1;
    s.meta[way].tag = tag;
    s.meta[way].pc_sig = pc_sig;
}

// --- Stats ---
uint64_t total_hits = 0, total_misses = 0, total_evictions = 0;
void PrintStats() {
    std::cout << "DS-RRIP: Hits=" << total_hits << " Misses=" << total_misses
              << " Evictions=" << total_evictions << std::endl;
}
void PrintStats_Heartbeat() {
    PrintStats();
}