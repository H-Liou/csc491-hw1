#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- SHiP-lite metadata ---
#define SHIP_TABLE_SIZE 512 // 2^9
#define SHIP_CTR_MAX 3      // 2 bits

struct BlockMeta {
    uint16_t pc_sig;     // 9 bits
    uint8_t reuse_ctr;   // 2 bits, dead-block approx
};

BlockMeta block_meta[LLC_SETS][LLC_WAYS];
uint8_t rrpv[LLC_SETS][LLC_WAYS]; // 2 bits per block

// SHiP table: 512 entries, 2 bits each
uint8_t ship_table[SHIP_TABLE_SIZE];

// --- Helper: PC signature hash ---
inline uint16_t GetPCSig(uint64_t PC) {
    // Use lower 9 bits of CRC32 of PC
    return champsim_crc2(PC) & 0x1FF;
}

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv)); // SRRIP: init to distant
    memset(block_meta, 0, sizeof(block_meta));
    memset(ship_table, 1, sizeof(ship_table)); // neutral start
}

// --- Victim selection (SRRIP) ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (rrpv[set][way] == 3)
                return way;
        }
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] < 3) ++rrpv[set][way];
    }
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
    // --- Get PC signature ---
    uint16_t pc_sig = GetPCSig(PC);

    // --- On hit ---
    if (hit) {
        rrpv[set][way] = 0; // MRU
        // Update SHiP table: reinforce reuse
        if (ship_table[pc_sig] < SHIP_CTR_MAX)
            ++ship_table[pc_sig];
        // Update block reuse counter
        if (block_meta[set][way].reuse_ctr < 3)
            ++block_meta[set][way].reuse_ctr;
        return;
    }

    // --- On fill ---
    // Predict deadness from SHiP and per-line dead-block counter
    uint8_t ship_pred = ship_table[pc_sig];
    uint8_t reuse_pred = block_meta[set][way].reuse_ctr;

    // If both SHiP and per-line reuse counter are low, insert at distant RRPV (dead)
    // If either is high, insert closer to MRU
    if (ship_pred <= 1 && reuse_pred <= 1) {
        rrpv[set][way] = 3; // Dead: favor eviction
    } else if (ship_pred >= 3 || reuse_pred >= 2) {
        rrpv[set][way] = 0; // Reusable: MRU
    } else {
        rrpv[set][way] = 2; // Neutral: mid RRPV
    }

    // Set block metadata
    block_meta[set][way].pc_sig = pc_sig;
    block_meta[set][way].reuse_ctr = 1; // Reset on fill

    // --- On eviction: decay SHiP if block not reused ---
    // Find victim way (the block being replaced)
    for (uint32_t vway = 0; vway < LLC_WAYS; ++vway) {
        if (current_set[vway].address == victim_addr) {
            uint16_t v_pc_sig = block_meta[set][vway].pc_sig;
            uint8_t v_reuse = block_meta[set][vway].reuse_ctr;
            if (v_reuse == 0 && ship_table[v_pc_sig] > 0)
                --ship_table[v_pc_sig]; // Penalize dead blocks
            block_meta[set][vway].reuse_ctr = 0; // Reset
            break;
        }
    }

    // --- Periodic decay of per-block reuse counters (phase adaptation) ---
    static uint64_t access_ctr = 0;
    ++access_ctr;
    if ((access_ctr & 0x3FFF) == 0) { // Every 16K accesses
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            for (uint32_t w = 0; w < LLC_WAYS; ++w)
                if (block_meta[s][w].reuse_ctr > 0)
                    --block_meta[s][w].reuse_ctr;
    }
}

// --- Print statistics ---
void PrintStats() {
    std::cout << "SL-DBARRIP: SHiP-lite + Dead-block Adaptive RRIP\n";
}
void PrintStats_Heartbeat() {}