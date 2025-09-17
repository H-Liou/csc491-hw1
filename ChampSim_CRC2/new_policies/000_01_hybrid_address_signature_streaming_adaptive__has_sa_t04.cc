#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// Metadata sizes
#define NUM_LEADER_SETS 32
#define PSEL_MAX 1023

// Per-block metadata
struct HAS_BlockMeta {
    uint8_t rrpv;         // 2 bits
    uint8_t pc_sig;       // 6 bits
    uint8_t addr_hash;    // 8 bits
};

std::vector<std::vector<HAS_BlockMeta>> block_meta;

// SHiP-lite: 2K-entry, 2 bits/counter
uint8_t ship_outcome[2048];

// Address-reuse table: 1K-entry, 2 bits/counter
uint8_t addr_reuse[1024];

// Streaming detector: 3 bits/set
struct StreamSet {
    uint64_t last_addr;
    int stride;
    uint8_t monotonic_count; // up to 7
    bool streaming;
};
StreamSet stream_sets[LLC_SETS];

// Set-dueling: 32 leader sets, 10-bit PSEL
uint16_t psel = PSEL_MAX / 2;
bool is_leader_set(uint32_t set) { return set < NUM_LEADER_SETS; }

// Helper: hash PC to 11 bits, address to 10 bits
inline uint16_t hash_pc(uint64_t PC) { return (PC ^ (PC >> 7)) & 0x7FF; }
inline uint16_t hash_addr(uint64_t addr) { return (addr ^ (addr >> 13)) & 0x3FF; }
inline uint8_t hash_addr8(uint64_t addr) { return (addr ^ (addr >> 17)) & 0xFF; }

// Initialize replacement state
void InitReplacementState() {
    block_meta.resize(LLC_SETS, std::vector<HAS_BlockMeta>(LLC_WAYS));
    memset(ship_outcome, 0, sizeof(ship_outcome));
    memset(addr_reuse, 0, sizeof(addr_reuse));
    memset(stream_sets, 0, sizeof(stream_sets));
    psel = PSEL_MAX / 2;
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
    // Streaming bypass: if streaming detected, bypass blocks with cold PC or cold address hash
    StreamSet &ss = stream_sets[set];
    uint16_t pc_sig = hash_pc(PC);
    uint16_t addr_sig = hash_addr(paddr);

    bool streaming = ss.streaming;
    bool cold_pc = ship_outcome[pc_sig] == 0;
    bool cold_addr = addr_reuse[addr_sig] == 0;

    if (streaming && (cold_pc || cold_addr)) {
        // Indicate bypass by returning LLC_WAYS (no fill)
        return LLC_WAYS;
    }

    // Standard RRIP victim selection
    for (int rrpv_val = 3; rrpv_val >= 0; --rrpv_val) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (block_meta[set][way].rrpv == rrpv_val) {
                return way;
            }
        }
    }
    // If none found, pick way 0 (shouldn't happen)
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
    HAS_BlockMeta &meta = block_meta[set][way];
    uint16_t pc_sig = hash_pc(PC);
    uint16_t addr_sig = hash_addr(paddr);
    uint8_t addr8 = hash_addr8(paddr);

    // Streaming detection: update stride and monotonic count
    StreamSet &ss = stream_sets[set];
    int stride = int(paddr) - int(ss.last_addr);
    if (stride == ss.stride && stride != 0) {
        if (ss.monotonic_count < 7) ss.monotonic_count++;
    } else {
        ss.stride = stride;
        ss.monotonic_count = 1;
    }
    ss.last_addr = paddr;
    ss.streaming = (ss.monotonic_count >= 3);

    // Update SHiP outcome counter
    if (hit) {
        if (ship_outcome[pc_sig] < 3) ship_outcome[pc_sig]++;
    } else {
        if (ship_outcome[pc_sig] > 0) ship_outcome[pc_sig]--;
    }

    // Update address reuse counter
    if (hit) {
        if (addr_reuse[addr_sig] < 3) addr_reuse[addr_sig]++;
    } else {
        if (addr_reuse[addr_sig] > 0) addr_reuse[addr_sig]--;
    }

    // Set-dueling: leader sets update PSEL
    bool is_leader = is_leader_set(set);
    if (is_leader) {
        // If hit and SRRIP, increment PSEL; if BRRIP, decrement
        bool srrip = (set % 2 == 0);
        if (hit) {
            if (srrip && psel < PSEL_MAX) psel++;
            else if (!srrip && psel > 0) psel--;
        }
    }

    // Insert new block: set PC signature and address hash
    meta.pc_sig = pc_sig;
    meta.addr_hash = addr8;

    // Insertion depth: combine global (SRRIP/BRRIP), PC, and address reuse
    bool use_brrip = (psel < PSEL_MAX / 2);
    bool hot_pc = ship_outcome[pc_sig] >= 2;
    bool hot_addr = addr_reuse[addr_sig] >= 2;

    if (ss.streaming && (!hot_pc || !hot_addr)) {
        // Streaming: bypass cold blocks (insert at LRU)
        meta.rrpv = 3;
    } else if (hot_pc || hot_addr) {
        // Hot reuse: insert at MRU
        meta.rrpv = 0;
    } else if (use_brrip) {
        // BRRIP: insert mostly at distant RRPV
        meta.rrpv = (rand() % 32 == 0) ? 0 : 2;
    } else {
        // SRRIP: insert at RRPV=2
        meta.rrpv = 2;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "HAS-SA Policy: End-of-simulation stats not implemented.\n";
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // No-op
}