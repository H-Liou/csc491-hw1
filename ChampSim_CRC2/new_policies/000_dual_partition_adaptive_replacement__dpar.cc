#include <vector>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// Tunable parameters
static const uint32_t PC_TABLE_SIZE    = 1024;
static const uint32_t REUSE_THRESHOLD  = 2;
static const uint32_t STRIDE_THRESHOLD = 2;
static const uint64_t EPOCH_LENGTH     = 100000;

// Replacement state
struct PCEntry {
    uint16_t reuse_count;
    uint16_t stride_count;
    uint64_t last_addr;
} PCtable[PC_TABLE_SIZE];

// Per-set LRU stack positions (0 = MRU, LLC_WAYS-1 = LRU)
static uint8_t lru_stack[LLC_SETS][LLC_WAYS];

// Dynamic partition boundary: [0, sep_ways-1]=temporal region, [sep_ways, LLC_WAYS-1]=spatial region
static uint32_t sep_ways = LLC_WAYS / 2;

// Epoch statistics
static uint64_t epoch_accesses = 0;
static uint64_t temporal_hits  = 0;
static uint64_t spatial_hits   = 0;

// Initialize replacement state
void InitReplacementState() {
    // Zero PC table
    for (uint32_t i = 0; i < PC_TABLE_SIZE; i++) {
        PCtable[i].reuse_count  = 0;
        PCtable[i].stride_count = 0;
        PCtable[i].last_addr    = 0;
    }
    // Initialize per-set LRU stacks
    for (uint32_t s = 0; s < LLC_SETS; s++) {
        for (uint32_t w = 0; w < LLC_WAYS; w++) {
            lru_stack[s][w] = w;
        }
    }
}

// Helper: update LRU within a region after an access in (set, way)
static void UpdateLRU(uint32_t set, uint32_t way, uint32_t low, uint32_t high) {
    uint8_t old_pos = lru_stack[set][way];
    // Increase position of all blocks in region that were more recent
    for (uint32_t w = low; w <= high; w++) {
        if (lru_stack[set][w] < old_pos) {
            lru_stack[set][w]++;
        }
    }
    // Make this block MRU
    lru_stack[set][way] = 0;
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
    // Classify this access
    uint32_t pc_idx = PC & (PC_TABLE_SIZE - 1);
    PCEntry &entry = PCtable[pc_idx];
    // Stride detection
    uint64_t stride = (entry.last_addr == 0) ? 0 : (paddr - entry.last_addr);
    if (stride != 0 && stride == (paddr - entry.last_addr)) {
        entry.stride_count++;
    } else {
        entry.stride_count = 1;
    }
    entry.last_addr = paddr;

    bool is_temporal = (entry.reuse_count >= REUSE_THRESHOLD);
    bool is_stream   = (entry.stride_count >= STRIDE_THRESHOLD);
    // Final region decision
    bool use_spatial = (!is_temporal && is_stream);

    // Determine region boundaries
    uint32_t low  = 0, high = 0;
    if (use_spatial) {
        low  = sep_ways;
        high = LLC_WAYS - 1;
        if (low > high) {
            // fallback to temporal if spatial region empty
            low  = 0; 
            high = sep_ways - 1;
        }
    } else {
        // temporal region
        low  = 0;
        high = sep_ways - 1;
        if (high < low) {
            // fallback to spatial if temporal empty
            low  = sep_ways;
            high = LLC_WAYS - 1;
        }
    }
    // Pick the LRU (max stack position) in [low, high]
    uint32_t victim = low;
    uint8_t maxpos = lru_stack[set][low];
    for (uint32_t w = low + 1; w <= high; w++) {
        if (lru_stack[set][w] > maxpos) {
            maxpos = lru_stack[set][w];
            victim = w;
        }
    }
    return victim;
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
    // Classify same as in GetVictimInSet
    uint32_t pc_idx = PC & (PC_TABLE_SIZE - 1);
    PCEntry &entry = PCtable[pc_idx];
    bool is_temporal = (entry.reuse_count >= REUSE_THRESHOLD);
    bool is_stream   = (entry.stride_count >= STRIDE_THRESHOLD);
    bool use_spatial = (!is_temporal && is_stream);

    // Count hits per region
    if (hit) {
        if (use_spatial) spatial_hits++;
        else             temporal_hits++;
        // Update reuse confidence on hit
        if (entry.reuse_count < 0xFFFF) entry.reuse_count++;
    } else {
        // On miss, decay reuse counter slowly
        if (entry.reuse_count > 0) entry.reuse_count--;
    }

    // Update per-set LRU
    // Decide region boundaries
    uint32_t low  = use_spatial ? sep_ways : 0;
    uint32_t high = use_spatial ? (LLC_WAYS - 1) : (sep_ways - 1);
    // Bounds check
    if (high < low) {
        low  = 0;
        high = LLC_WAYS - 1;
    }
    UpdateLRU(set, way, low, high);

    // Epoch-driven partition adjustment
    epoch_accesses++;
    if (epoch_accesses >= EPOCH_LENGTH) {
        // Shift partition toward whichever region wins
        if (temporal_hits > spatial_hits && sep_ways < (LLC_WAYS - 1)) {
            sep_ways++;
        } else if (spatial_hits > temporal_hits && sep_ways > 1) {
            sep_ways--;
        }
        // Reset epoch stats
        epoch_accesses = 0;
        temporal_hits  = 0;
        spatial_hits   = 0;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "DPAR Partition Size (temporal ways): " << sep_ways << "\n";
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    std::cout << "[Heartbeat] sep_ways=" << sep_ways
              << " last_epoch_hits(T/S)=(" << temporal_hits
              << "/" << spatial_hits << ")\n";
}