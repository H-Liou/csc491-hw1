#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// DRRIP: Set-dueling (64 leader sets), 10-bit PSEL
#define NUM_LEADER_SETS 64
#define PSEL_BITS 10
uint16_t psel = (1 << (PSEL_BITS - 1)); // start neutral
std::vector<uint32_t> sr_leader_sets, br_leader_sets;

// Per-block: RRPV (2 bits)
struct BlockMeta {
    uint8_t rrpv; // 2 bits
};
BlockMeta meta[LLC_SETS][LLC_WAYS];

// Streaming detector: per-set last address, stride, stream count (3 bits)
struct StreamDetect {
    uint64_t last_addr;
    int64_t last_stride;
    uint8_t stream_cnt; // 3 bits
};
StreamDetect stream_meta[LLC_SETS];

// Per-set dead-block counter (2 bits per set)
uint8_t set_dead_ctr[LLC_SETS];

// Periodic decay: heartbeat counter
uint64_t heartbeat = 0;

// Helper: assign leader sets
void InitLeaderSets() {
    sr_leader_sets.clear();
    br_leader_sets.clear();
    // First half: SRRIP leaders, second half: BRRIP leaders
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i) {
        if (i < NUM_LEADER_SETS / 2) sr_leader_sets.push_back(i);
        else br_leader_sets.push_back(i);
    }
}

// Initialize replacement state
void InitReplacementState() {
    memset(meta, 0, sizeof(meta));
    memset(stream_meta, 0, sizeof(stream_meta));
    memset(set_dead_ctr, 0, sizeof(set_dead_ctr));
    heartbeat = 0;
    psel = (1 << (PSEL_BITS - 1));
    InitLeaderSets();
}

// Find victim in the set (prefer invalid, else RRPV==3, else increment RRPV)
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (!current_set[way].valid)
            return way;
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
    // --- Streaming detector ---
    StreamDetect &sd = stream_meta[set];
    int64_t stride = paddr - sd.last_addr;
    if (sd.last_stride != 0 && stride == sd.last_stride) {
        if (sd.stream_cnt < 7) sd.stream_cnt++;
    } else {
        sd.stream_cnt = 0;
    }
    sd.last_stride = stride;
    sd.last_addr = paddr;

    // --- On hit: promote to MRU ---
    if (hit) {
        meta[set][way].rrpv = 0;
        return;
    }

    // --- Dead-block detection (eviction without reuse) ---
    // If we fill over a valid block whose rrpv==3, and it was not recently reused
    // Increment per-set dead-block counter
    if (meta[set][way].rrpv == 3 && !hit) {
        if (set_dead_ctr[set] < 3) set_dead_ctr[set]++;
    }

    // --- DRRIP insertion depth ---
    bool is_sr_leader = std::find(sr_leader_sets.begin(), sr_leader_sets.end(), set) != sr_leader_sets.end();
    bool is_br_leader = std::find(br_leader_sets.begin(), br_leader_sets.end(), set) != br_leader_sets.end();
    uint8_t ins_rrpv = 2; // SRRIP default

    if (is_sr_leader) {
        ins_rrpv = 2;
    } else if (is_br_leader) {
        ins_rrpv = 3;
    } else {
        // Follower sets: use global PSEL
        if (psel >= (1 << (PSEL_BITS - 1)))
            ins_rrpv = 2; // favor SRRIP
        else
            ins_rrpv = 3; // favor BRRIP
    }

    // --- Streaming override ---
    if (sd.stream_cnt >= 4) {
        ins_rrpv = 3; // streaming: insert at distant (or could bypass)
    }

    // --- Dead-block override ---
    if (set_dead_ctr[set] >= 2) {
        ins_rrpv = 3; // set has high dead-block rate, use distant insertion
    }

    meta[set][way].rrpv = ins_rrpv;

    // --- Update PSEL on leader sets ---
    // On replacement: if hit, reward SRRIP; if miss, reward BRRIP
    if (is_sr_leader && !hit) {
        if (psel > 0) psel--;
    } else if (is_br_leader && hit) {
        if (psel < ((1 << PSEL_BITS) - 1)) psel++;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    uint32_t sets_dead = 0, stream_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s) {
        if (set_dead_ctr[s] >= 2) sets_dead++;
        if (stream_meta[s].stream_cnt >= 4) stream_sets++;
    }
    std::cout << "DRRIP+Stream+Dead: sets_dead=" << sets_dead
              << ", stream_sets=" << stream_sets
              << ", psel=" << psel << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    heartbeat++;
    if (heartbeat % 100000 == 0) {
        // Decay dead-block counters
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            if (set_dead_ctr[s] > 0)
                set_dead_ctr[s]--;
        // Decay streaming counters
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            if (stream_meta[s].stream_cnt > 0)
                stream_meta[s].stream_cnt--;
    }
}