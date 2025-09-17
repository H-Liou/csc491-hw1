#include <vector>
#include <cstdint>
#include <cstring>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- SHiP-lite PC signature predictor ---
#define SHIP_PC_BITS 6
#define SHIP_ENTRY_COUNT 1024
#define SHIP_COUNTER_BITS 2

struct SHIPEntry {
    uint8_t counter; // 2 bits
    uint8_t last_rrpv; // Used for optional update, not strictly needed
};

SHIPEntry ship_table[SHIP_ENTRY_COUNT];

// --- Address-based reuse predictor ---
#define ADDR_TAG_BITS 8
#define ADDR_ENTRY_COUNT 1024
#define ADDR_COUNTER_BITS 2

struct ADDREntry {
    uint32_t tag;
    uint8_t counter; // 2 bits
};

ADDREntry addr_table[ADDR_ENTRY_COUNT];

// --- Per-block metadata ---
struct BLOCK_META {
    uint8_t rrpv; // 2 bits
    uint8_t ship_sig; // 6 bits
    uint8_t addr_sig; // 8 bits
};

BLOCK_META block_meta[LLC_SETS][LLC_WAYS];

// --- Streaming Detector (per-set) ---
#define STREAM_WINDOW 8
#define STREAM_DETECTOR_BITS 2

struct STREAM_DETECTOR {
    int32_t last_addr;
    int32_t last_delta;
    uint8_t stream_score; // 2 bits
};

STREAM_DETECTOR stream_detector[LLC_SETS];

// --- Helper functions ---
inline uint16_t get_ship_index(uint64_t PC) {
    return ((PC >> 2) ^ (PC >> 11)) & (SHIP_ENTRY_COUNT - 1);
}

inline uint16_t get_addr_index(uint64_t paddr) {
    return ((paddr >> 6) ^ (paddr >> 13)) & (ADDR_ENTRY_COUNT - 1);
}

inline uint8_t get_addr_sig(uint64_t paddr) {
    return (paddr >> 6) & 0xFF;
}

// Initialize replacement state
void InitReplacementState() {
    std::memset(ship_table, 0, sizeof(ship_table));
    std::memset(addr_table, 0, sizeof(addr_table));
    std::memset(block_meta, 0, sizeof(block_meta));
    std::memset(stream_detector, 0, sizeof(stream_detector));
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            block_meta[set][way].rrpv = 3; // insert as distant by default
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
    // Streaming bypass: If streaming detected, prefer to bypass
    if (stream_detector[set].stream_score >= 2) {
        // Find block with RRPV==3, else increment everyone and try again
        for (int round = 0; round < 2; ++round) {
            for (uint32_t way = 0; way < LLC_WAYS; ++way) {
                if (block_meta[set][way].rrpv == 3)
                    return way;
            }
            // Increment RRPV
            for (uint32_t way = 0; way < LLC_WAYS; ++way)
                if (block_meta[set][way].rrpv < 3)
                    ++block_meta[set][way].rrpv;
        }
    } else {
        // Normal: find RRPV==3
        for (int round = 0; round < 2; ++round) {
            for (uint32_t way = 0; way < LLC_WAYS; ++way) {
                if (block_meta[set][way].rrpv == 3)
                    return way;
            }
            for (uint32_t way = 0; way < LLC_WAYS; ++way)
                if (block_meta[set][way].rrpv < 3)
                    ++block_meta[set][way].rrpv;
        }
    }
    // Fallback
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
    // --- Streaming Detector update ---
    int32_t cur_addr = (int32_t)(paddr >> 6);
    int32_t delta = cur_addr - stream_detector[set].last_addr;
    if (stream_detector[set].last_addr != 0) {
        if (stream_detector[set].last_delta == delta && delta != 0) {
            if (stream_detector[set].stream_score < 3)
                ++stream_detector[set].stream_score;
        } else if (delta != 0) {
            if (stream_detector[set].stream_score > 0)
                --stream_detector[set].stream_score;
        }
        stream_detector[set].last_delta = delta;
    }
    stream_detector[set].last_addr = cur_addr;

    // --- SHiP-lite update ---
    uint16_t ship_idx = get_ship_index(PC);
    if (hit) {
        if (ship_table[ship_idx].counter < 3)
            ++ship_table[ship_idx].counter;
    } else {
        if (ship_table[ship_idx].counter > 0)
            --ship_table[ship_idx].counter;
    }

    // --- Address-based update ---
    uint16_t addr_idx = get_addr_index(paddr);
    uint8_t addr_sig = get_addr_sig(paddr);
    if (hit) {
        if (addr_table[addr_idx].counter < 3)
            ++addr_table[addr_idx].counter;
    } else {
        if (addr_table[addr_idx].counter > 0)
            --addr_table[addr_idx].counter;
    }
    addr_table[addr_idx].tag = addr_sig;

    // --- Per-block meta update ---
    block_meta[set][way].ship_sig = ship_idx & 0x3F;
    block_meta[set][way].addr_sig = addr_sig;

    // --- RRPV update for fill ---
    if (!hit) {
        // Streaming detected: insert at distant or bypass (if possible)
        if (stream_detector[set].stream_score >= 2) {
            block_meta[set][way].rrpv = 3;
            return;
        }
        // Reuse prediction
        bool strong_ship = ship_table[ship_idx].counter >= 2;
        bool strong_addr = addr_table[addr_idx].counter >= 2;
        if (strong_ship || strong_addr)
            block_meta[set][way].rrpv = 0; // Insert close to MRU
        else
            block_meta[set][way].rrpv = 3; // Insert distant
    } else {
        // On hit, promote towards MRU
        if (block_meta[set][way].rrpv > 0)
            --block_meta[set][way].rrpv;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "SASH: SHiP table, Addr table, and Streaming detector metadata summary:\n";
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
}