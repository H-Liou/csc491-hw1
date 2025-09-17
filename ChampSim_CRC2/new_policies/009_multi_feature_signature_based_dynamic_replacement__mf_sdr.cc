#include <vector>
#include <cstdint>
#include <iostream>
#include <algorithm>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// RRIP parameters
#define RRPV_BITS 2
#define RRPV_MAX ((1 << RRPV_BITS) - 1)
#define RRPV_LONG RRPV_MAX
#define RRPV_SHORT (RRPV_MAX - 1)
#define RRPV_PROTECT 0

// Signature table parameters
#define SIGTAB_SIZE 4096
#define SIGTAB_COUNTER_MAX 7
#define SIGTAB_COUNTER_MIN 0

struct BlockMeta {
    bool valid;
    uint64_t tag;
    uint8_t rrpv;
    uint16_t signature;
    uint8_t recency; // Simple recency counter
};

struct SetMeta {
    BlockMeta blocks[LLC_WAYS];
};

std::vector<SetMeta> sets;

// Signature table: maps signature to reuse counter
struct SignatureEntry {
    uint8_t reuse_counter;
};

std::vector<SignatureEntry> sig_table;

// Helper: generate signature from PC and address region
inline uint16_t gen_signature(uint64_t PC, uint64_t paddr) {
    // Use lower bits of PC and upper bits of address region
    return ((PC & 0xFF) << 4) | ((paddr >> 12) & 0xF);
}

// Initialize replacement state
void InitReplacementState() {
    sets.clear();
    sets.resize(LLC_SETS);
    for (auto& set : sets) {
        for (int i = 0; i < LLC_WAYS; ++i) {
            set.blocks[i].valid = false;
            set.blocks[i].tag = 0;
            set.blocks[i].rrpv = RRPV_LONG;
            set.blocks[i].signature = 0;
            set.blocks[i].recency = 0;
        }
    }
    sig_table.clear();
    sig_table.resize(SIGTAB_SIZE);
    for (auto& entry : sig_table)
        entry.reuse_counter = 3; // Start neutral
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
    // Try to find a block with RRPV_MAX
    for (int loop = 0; loop < 2; ++loop) {
        for (int i = 0; i < LLC_WAYS; ++i) {
            if (meta.blocks[i].valid && meta.blocks[i].rrpv == RRPV_MAX)
                return i;
            if (!meta.blocks[i].valid)
                return i; // Empty slot
        }
        // If none found, increment all RRPVs and repeat
        for (int i = 0; i < LLC_WAYS; ++i)
            if (meta.blocks[i].rrpv < RRPV_MAX)
                meta.blocks[i].rrpv++;
    }
    // Fallback: evict block with highest RRPV, break ties by lowest recency
    uint32_t victim = 0;
    for (int i = 1; i < LLC_WAYS; ++i) {
        if (meta.blocks[i].rrpv > meta.blocks[victim].rrpv)
            victim = i;
        else if (meta.blocks[i].rrpv == meta.blocks[victim].rrpv &&
                 meta.blocks[i].recency < meta.blocks[victim].recency)
            victim = i;
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
    SetMeta &meta = sets[set];
    uint64_t tag = (paddr >> 6); // 64B lines
    uint16_t sig = gen_signature(PC, paddr);
    uint32_t sig_idx = sig % SIGTAB_SIZE;

    BlockMeta &blk = meta.blocks[way];

    // On hit: promote and update signature table
    if (hit) {
        blk.rrpv = RRPV_PROTECT;
        blk.recency = 7; // Highest recency

        // Increment signature reuse counter (up to max)
        if (sig_table[sig_idx].reuse_counter < SIGTAB_COUNTER_MAX)
            sig_table[sig_idx].reuse_counter++;

        // If same signature, further protect
        if (blk.signature == sig)
            blk.rrpv = RRPV_PROTECT;
    } else {
        // On miss: insert new block
        blk.valid = true;
        blk.tag = tag;
        blk.signature = sig;
        blk.recency = 7;

        // Use signature table to decide insertion RRPV
        uint8_t reuse_val = sig_table[sig_idx].reuse_counter;
        if (reuse_val >= 5)
            blk.rrpv = RRPV_PROTECT; // strong reuse
        else if (reuse_val >= 3)
            blk.rrpv = RRPV_SHORT;   // moderate reuse
        else
            blk.rrpv = RRPV_LONG;    // weak reuse (likely transient)

        // On insertion, decay signature reuse counter (unless strong)
        if (reuse_val > SIGTAB_COUNTER_MIN)
            sig_table[sig_idx].reuse_counter--;
    }

    // Decay recency of other blocks in set
    for (int i = 0; i < LLC_WAYS; ++i) {
        if (i != way && meta.blocks[i].recency > 0)
            meta.blocks[i].recency--;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    // Print signature table reuse counter histogram
    uint64_t hist[SIGTAB_COUNTER_MAX+1] = {0};
    for (const auto& entry : sig_table)
        hist[entry.reuse_counter]++;
    std::cout << "Signature reuse counter histogram: ";
    for (int i = 0; i <= SIGTAB_COUNTER_MAX; ++i)
        std::cout << "[" << i << "]=" << hist[i] << " ";
    std::cout << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // No-op
}