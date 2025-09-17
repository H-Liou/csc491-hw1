#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// DRRIP: 2-bit RRPV per block
struct BlockMeta {
    uint8_t rrpv; // 2 bits
};
BlockMeta meta[LLC_SETS][LLC_WAYS];

// DIP/DRRIP set-dueling: 64 leader sets (SRRIP vs LIP)
#define NUM_LEADER_SETS 64
#define PSEL_BITS 10
uint16_t psel = 1 << (PSEL_BITS - 1); // 10-bit selector, midpoint

// Use fixed mapping for leader sets: first 32 = SRRIP, next 32 = LIP
bool IsSRRIPLeader(uint32_t set) { return set < 32; }
bool IsLIPLeader(uint32_t set)   { return set >= 32 && set < 64; }

// Streaming detector: last address, delta, 2-bit confidence per set
struct StreamDetect {
    uint64_t last_addr;
    int64_t last_delta;
    uint8_t stream_conf; // 2 bits, saturating
};
StreamDetect stream_meta[LLC_SETS];

// Streaming detector: returns true if stream detected in this set
inline bool IsStreaming(uint32_t set, uint64_t paddr) {
    StreamDetect &sd = stream_meta[set];
    int64_t delta = paddr - sd.last_addr;
    bool is_stream = false;
    if (sd.last_addr != 0) {
        if (delta == sd.last_delta && delta != 0) {
            if (sd.stream_conf < 3) sd.stream_conf++;
        } else {
            if (sd.stream_conf > 0) sd.stream_conf--;
        }
        if (sd.stream_conf >= 2) is_stream = true;
    }
    sd.last_delta = delta;
    sd.last_addr = paddr;
    return is_stream;
}

// Initialize replacement state
void InitReplacementState() {
    memset(meta, 0, sizeof(meta));
    memset(stream_meta, 0, sizeof(stream_meta));
    psel = 1 << (PSEL_BITS - 1); // Midpoint
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
    // 1. Prefer invalid blocks
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (!current_set[way].valid)
            return way;

    // 2. RRIP victim search
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (meta[set][way].rrpv == 3)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (meta[set][way].rrpv < 3)
                meta[set][way].rrpv++;
    }
    return 0; // Should not reach
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
    // --- Streaming detection ---
    bool is_stream = IsStreaming(set, paddr);

    // --- On hit: promote to MRU ---
    if (hit) {
        meta[set][way].rrpv = 0;
        return;
    }

    // --- Streaming bypass: do not insert block if stream detected ---
    if (is_stream) {
        // Do not update meta: bypass insertion (block is not cached)
        return;
    }

    // --- DRRIP insertion depth selection ---
    uint8_t ins_rrpv = 2; // Default: SRRIP
    bool sr_leader = IsSRRIPLeader(set);
    bool lip_leader = IsLIPLeader(set);

    if (sr_leader) {
        ins_rrpv = 2; // SRRIP: insert at RRIP=2
    } else if (lip_leader) {
        ins_rrpv = 3; // LIP: insert at RRIP=3 (LRU)
    } else {
        // Follower: use PSEL to choose policy
        if (psel >= (1 << (PSEL_BITS - 1)))
            ins_rrpv = 2; // SRRIP
        else
            ins_rrpv = 3; // LIP
    }
    meta[set][way].rrpv = ins_rrpv;

    // --- Set-dueling: update PSEL on leader set evictions ---
    // If a block is evicted from a leader set, update PSEL
    // If hit==0, victim_addr is the address of the block being evicted (not reused)
    if (sr_leader && !hit) {
        // SRRIP leader: increment PSEL if block not reused
        if (psel < ((1 << PSEL_BITS) - 1)) psel++;
    }
    if (lip_leader && !hit) {
        // LIP leader: decrement PSEL if block not reused
        if (psel > 0) psel--;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    // Print PSEL value and streaming set count
    uint32_t stream_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (stream_meta[s].stream_conf >= 2) stream_sets++;
    std::cout << "DLHB: streaming sets=" << stream_sets << "/" << LLC_SETS
              << ", PSEL=" << psel << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // No periodic state to update (streaming detector saturates independently)
}