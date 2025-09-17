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
#define RRIP_LONG RRIP_MAX
#define RRIP_SHORT 0
#define RRIP_MEDIUM 1

// PC-based predictor
#define PC_PRED_SIZE 8192
#define PC_PRED_BITS 2
#define PC_PRED_MAX ((1 << PC_PRED_BITS) - 1)
#define PC_PRED_THRESHOLD 2

// Spatial locality tracker
#define SPATIAL_WINDOW 32
#define SPATIAL_STRIDE_THRESHOLD 0.7

// Phase detector
#define PHASE_WINDOW 64
#define PHASE_HIGH 0.38
#define PHASE_LOW 0.15

struct BlockMeta {
    uint8_t rrip;
    bool valid;
};

struct SetMeta {
    BlockMeta blocks[LLC_WAYS];

    // For spatial locality
    uint64_t last_addr;
    int64_t stride_sum;
    uint32_t stride_count;
    uint32_t spatial_pattern_count;

    // For phase detection
    uint32_t access_count;
    uint32_t hit_count;
    bool protective_mode;

    SetMeta() : last_addr(0), stride_sum(0), stride_count(0), spatial_pattern_count(0),
                access_count(0), hit_count(0), protective_mode(true) {
        for (int i = 0; i < LLC_WAYS; ++i) {
            blocks[i].rrip = RRIP_MAX;
            blocks[i].valid = false;
        }
    }
};

struct PCPredictorEntry {
    uint8_t reuse_counter;
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
        entry.reuse_counter = PC_PRED_MAX / 2;
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

    // --- PC-based reuse predictor update ---
    uint32_t pc_idx = pc_hash(PC);
    if (hit) {
        if (pc_predictor[pc_idx].reuse_counter < PC_PRED_MAX)
            pc_predictor[pc_idx].reuse_counter++;
    } else {
        if (pc_predictor[pc_idx].reuse_counter > 0)
            pc_predictor[pc_idx].reuse_counter--;
    }

    // --- Spatial locality tracking ---
    if (meta.stride_count < SPATIAL_WINDOW) {
        if (meta.stride_count > 0) {
            int64_t stride = int64_t(paddr) - int64_t(meta.last_addr);
            // Only consider strides within a reasonable range (filter out random jumps)
            if (stride != 0 && std::abs(stride) < 1024*128) {
                meta.stride_sum += stride;
                // If stride matches previous stride, count as spatial pattern
                if (meta.stride_count > 1) {
                    int64_t avg_stride = meta.stride_sum / (meta.stride_count-1);
                    if (std::abs(stride - avg_stride) < 64) // within 1 cache line
                        meta.spatial_pattern_count++;
                }
            }
        }
        meta.stride_count++;
        meta.last_addr = paddr;
    } else {
        // Reset window
        meta.stride_sum = 0;
        meta.stride_count = 1;
        meta.spatial_pattern_count = 0;
        meta.last_addr = paddr;
    }

    // --- Phase detection ---
    if (hit) {
        meta.hit_count++;
        meta.blocks[way].rrip = RRIP_SHORT;
        meta.blocks[way].valid = true;
    } else {
        // Decide insertion RRIP
        uint8_t insert_rrip = RRIP_LONG;
        bool spatial_good = false;
        if (meta.stride_count > 2) {
            float spatial_score = float(meta.spatial_pattern_count) / float(meta.stride_count-1);
            if (spatial_score > SPATIAL_STRIDE_THRESHOLD)
                spatial_good = true;
        }

        if (pc_predictor[pc_idx].reuse_counter >= PC_PRED_THRESHOLD || spatial_good)
            insert_rrip = RRIP_SHORT;
        else if (meta.protective_mode)
            insert_rrip = RRIP_MEDIUM;

        meta.blocks[way].rrip = insert_rrip;
        meta.blocks[way].valid = true;
    }

    // Every PHASE_WINDOW accesses, adapt insertion mode based on hit rate
    if (meta.access_count % PHASE_WINDOW == 0) {
        float hit_rate = float(meta.hit_count) / float(PHASE_WINDOW);
        if (hit_rate > PHASE_HIGH)
            meta.protective_mode = true;
        else if (hit_rate < PHASE_LOW)
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