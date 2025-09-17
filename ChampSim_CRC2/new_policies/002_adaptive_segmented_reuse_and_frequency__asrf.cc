#include <vector>
#include <cstdint>
#include <iostream>
#include <algorithm>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// Segment sizes
constexpr int REUSE_SEG_SIZE = 6;    // Ways in Reuse Segment
constexpr int FREQ_SEG_SIZE = LLC_WAYS - REUSE_SEG_SIZE; // Ways in Frequency Segment

// Replacement state per block
struct BlockState {
    uint32_t reuse_counter;    // Recent reuse (decays over time)
    uint32_t freq_counter;     // Frequency of hits (decays slowly)
    uint64_t last_access_time; // For tie-breaking
    bool in_reuse_seg;         // Segment tag
};

std::vector<std::vector<BlockState>> block_state(LLC_SETS, std::vector<BlockState>(LLC_WAYS));
uint64_t global_access_counter = 0;

// Stats
uint64_t total_evictions = 0;
uint64_t reuse_evictions = 0;
uint64_t freq_evictions = 0;

void InitReplacementState() {
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            block_state[set][way] = {0, 0, 0, way < REUSE_SEG_SIZE};
        }
    }
    global_access_counter = 0;
    total_evictions = 0;
    reuse_evictions = 0;
    freq_evictions = 0;
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
    global_access_counter++;

    // Prefer to evict from Frequency Segment first
    int victim_way = -1;
    int min_freq_score = 0x7fffffff;
    int min_reuse_score = 0x7fffffff;
    int freq_victim = -1;
    int reuse_victim = -1;

    // Scan Frequency Segment
    for (int way = REUSE_SEG_SIZE; way < LLC_WAYS; ++way) {
        BlockState& bs = block_state[set][way];
        int score = bs.freq_counter * 2 + bs.reuse_counter + (int)(global_access_counter - bs.last_access_time)/32;
        if (score < min_freq_score) {
            min_freq_score = score;
            freq_victim = way;
        }
    }

    // Scan Reuse Segment (only if Frequency Segment is full of high-frequency blocks)
    for (int way = 0; way < REUSE_SEG_SIZE; ++way) {
        BlockState& bs = block_state[set][way];
        int score = bs.reuse_counter * 3 + (int)(global_access_counter - bs.last_access_time)/16;
        if (score < min_reuse_score) {
            min_reuse_score = score;
            reuse_victim = way;
        }
    }

    // If Frequency Segment victim has very low frequency and reuse, evict it
    if (min_freq_score <= 8) {
        victim_way = freq_victim;
        freq_evictions++;
    }
    else {
        // Otherwise, evict least recently reused block from Reuse Segment
        victim_way = reuse_victim;
        reuse_evictions++;
    }
    total_evictions++;

    return victim_way;
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
    global_access_counter++;
    BlockState& bs = block_state[set][way];

    bs.last_access_time = global_access_counter;

    // Decay counters periodically
    if (global_access_counter % 256 == 0) {
        for (int w = 0; w < LLC_WAYS; ++w) {
            block_state[set][w].reuse_counter = block_state[set][w].reuse_counter / 2;
            block_state[set][w].freq_counter = block_state[set][w].freq_counter / 2;
        }
    }

    if (hit) {
        bs.reuse_counter = std::min(bs.reuse_counter + 2, 15u);
        bs.freq_counter = std::min(bs.freq_counter + 1, 15u);

        // Promote to Reuse Segment if not already there and reuse is high
        if (!bs.in_reuse_seg && bs.reuse_counter >= 4) {
            // Find a block in Reuse Segment with lowest reuse to demote
            int min_reuse = 0x7fffffff, demote_way = -1;
            for (int w = 0; w < REUSE_SEG_SIZE; ++w) {
                if (block_state[set][w].reuse_counter < min_reuse) {
                    min_reuse = block_state[set][w].reuse_counter;
                    demote_way = w;
                }
            }
            if (demote_way != -1 && bs.reuse_counter > block_state[set][demote_way].reuse_counter) {
                std::swap(block_state[set][way], block_state[set][demote_way]);
                block_state[set][demote_way].in_reuse_seg = false;
                block_state[set][way].in_reuse_seg = true;
            }
        }
    } else {
        // On miss, decay reuse counter
        bs.reuse_counter = bs.reuse_counter / 2;
        // If in Reuse Segment and reuse falls low, demote to Frequency Segment
        if (bs.in_reuse_seg && bs.reuse_counter < 2) {
            // Find a block in Frequency Segment with lowest frequency to promote
            int min_freq = 0x7fffffff, promote_way = -1;
            for (int w = REUSE_SEG_SIZE; w < LLC_WAYS; ++w) {
                if (block_state[set][w].freq_counter < min_freq) {
                    min_freq = block_state[set][w].freq_counter;
                    promote_way = w;
                }
            }
            if (promote_way != -1) {
                std::swap(block_state[set][way], block_state[set][promote_way]);
                block_state[set][promote_way].in_reuse_seg = true;
                block_state[set][way].in_reuse_seg = false;
            }
        }
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "ASRF: total_evictions=" << total_evictions
              << " reuse_evictions=" << reuse_evictions
              << " freq_evictions=" << freq_evictions
              << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    PrintStats();
}