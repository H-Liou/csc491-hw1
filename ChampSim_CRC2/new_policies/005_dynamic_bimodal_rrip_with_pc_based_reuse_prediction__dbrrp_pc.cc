#include <vector>
#include <cstdint>
#include <iostream>
#include <unordered_map>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// SRRIP parameters
#define RRIP_BITS 2
#define RRIP_MAX ((1 << RRIP_BITS) - 1)
#define RRIP_LONG RRIP_MAX      // Insert as "distant re-reference"
#define RRIP_SHORT 0            // Insert as "imminent re-reference"
#define RRIP_MEDIUM 1           // Insert as "medium re-reference"

// Bimodal insertion parameters
#define BIMODAL_WINDOW 64
#define BIMODAL_HIGH 0.38
#define BIMODAL_LOW 0.15

// PC-based predictor parameters
#define PC_PRED_SIZE 8192
#define PC_PRED_BITS 2
#define PC_PRED_MAX ((1 << PC_PRED_BITS) - 1)
#define PC_PRED_THRESHOLD 2    // >=2 means "reuse likely"

struct BlockMeta {
    uint8_t rrip;
    bool valid;
};

struct SetMeta {
    BlockMeta blocks[LLC_WAYS];
    uint32_t access_count;
    uint32_t hit_count;
    bool protective_mode; // If true, insert with RRIP_MEDIUM, else RRIP_LONG
    SetMeta() : access_count(0), hit_count(0), protective_mode(true) {
        for (int i = 0; i < LLC_WAYS; ++i) {
            blocks[i].rrip = RRIP_MAX;
            blocks[i].valid = false;
        }
    }
};

// Simple global PC-based reuse predictor (indexed by PC hash)
struct PCPredictorEntry {
    uint8_t reuse_counter; // saturating up/down counter
};
std::vector<SetMeta> sets;
std::vector<PCPredictorEntry> pc_predictor;

// Hash PC to predictor index
inline uint32_t pc_hash(uint64_t PC) {
    return (PC ^ (PC >> 2) ^ (PC >> 5)) & (PC_PRED_SIZE - 1);
}

// Initialize replacement state
void InitReplacementState() {
    sets.clear();
    sets.resize(LLC_SETS);
    pc_predictor.clear();
    pc_predictor.resize(PC_PRED_SIZE);
    for (auto& entry : pc_predictor)
        entry.reuse_counter = PC_PRED_MAX / 2; // Initialize to neutral
}

// Find victim in the set
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    SetMeta &meta = sets[set];

    // Prefer invalid blocks first
    for (uint32_t i = 0; i < LLC_WAYS; ++i)
        if (!meta.blocks[i].valid)
            return i;

    // Find blocks with RRIP_MAX
    for (uint32_t round = 0; round < 2; ++round) {
        for (uint32_t i = 0; i < LLC_WAYS; ++i) {
            if (meta.blocks[i].rrip == RRIP_MAX)
                return i;
        }
        // Increment RRIP of all blocks if none found
        for (uint32_t i = 0; i < LLC_WAYS; ++i)
            if (meta.blocks[i].rrip < RRIP_MAX)
                meta.blocks[i].rrip++;
    }

    // Fallback: evict way 0
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
    SetMeta &meta = sets[set];
    meta.access_count++;

    // Update PC-based predictor
    uint32_t pc_idx = pc_hash(PC);
    if (hit) {
        if (pc_predictor[pc_idx].reuse_counter < PC_PRED_MAX)
            pc_predictor[pc_idx].reuse_counter++;
    } else {
        if (pc_predictor[pc_idx].reuse_counter > 0)
            pc_predictor[pc_idx].reuse_counter--;
    }

    if (hit) {
        meta.hit_count++;
        meta.blocks[way].rrip = RRIP_SHORT;
        meta.blocks[way].valid = true;
    } else {
        // Choose RRIP insertion value
        uint8_t insert_rrip = RRIP_LONG;
        if (pc_predictor[pc_idx].reuse_counter >= PC_PRED_THRESHOLD)
            insert_rrip = RRIP_SHORT; // PC shows reuse: protect
        else if (meta.protective_mode)
            insert_rrip = RRIP_MEDIUM; // Set in high-locality mode
        meta.blocks[way].rrip = insert_rrip;
        meta.blocks[way].valid = true;
    }

    // Every BIMODAL_WINDOW accesses, adapt insertion mode based on hit rate
    if (meta.access_count % BIMODAL_WINDOW == 0) {
        float hit_rate = float(meta.hit_count) / float(BIMODAL_WINDOW);
        if (hit_rate > BIMODAL_HIGH)
            meta.protective_mode = true;
        else if (hit_rate < BIMODAL_LOW)
            meta.protective_mode = false;
        meta.hit_count = 0;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    uint64_t protected_sets = 0;
    for (const auto& meta : sets)
        if (meta.protective_mode) protected_sets++;
    std::cout << "Fraction of sets in protective mode: " << double(protected_sets) / LLC_SETS << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // No-op
}