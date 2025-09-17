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
    uint8_t dead; // 1 bit
};
BlockMeta meta[LLC_SETS][LLC_WAYS];

// DIP-style set-dueling: 32 leader sets, 10-bit PSEL
#define NUM_LEADER_SETS 32
std::vector<uint32_t> leader_sets_LIP;
std::vector<uint32_t> leader_sets_BIP;
uint16_t PSEL = 512; // 10-bit

// Streaming detector: per 32 sets
struct StreamDetect {
    uint64_t last_addr;
    int64_t last_stride;
    uint8_t stream_cnt; // 3 bits
    uint8_t reuse_cnt;  // 2 bits
};
StreamDetect stream_meta[NUM_LEADER_SETS];

// Streaming leader sets: sets 0..31
std::vector<uint32_t> stream_leader_sets;

// Helper: assign leader and streaming sets
void InitLeaderSets() {
    leader_sets_LIP.clear();
    leader_sets_BIP.clear();
    stream_leader_sets.clear();
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i) {
        leader_sets_LIP.push_back(i);
        leader_sets_BIP.push_back(i + NUM_LEADER_SETS);
        stream_leader_sets.push_back(i);
    }
}

// Initialize replacement state
void InitReplacementState() {
    memset(meta, 0, sizeof(meta));
    memset(stream_meta, 0, sizeof(stream_meta));
    InitLeaderSets();
    PSEL = 512;
}

// Find victim in the set: prefer invalid, else dead-block, else RRPV==3, else increment RRPV
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // 1. Prefer invalid
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (!current_set[way].valid)
            return way;
    // 2. Prefer dead-block
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (meta[set][way].dead)
            return way;
    // 3. Prefer RRPV==3
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (meta[set][way].rrpv == 3)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (meta[set][way].rrpv < 3)
                meta[set][way].rrpv++;
    }
    return 0; // unreachable
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
    // --- Streaming detection (in streaming leader sets) ---
    uint8_t is_stream_leader = 0;
    int stream_idx = -1;
    for (int i = 0; i < NUM_LEADER_SETS; ++i) {
        if (set == stream_leader_sets[i]) {
            is_stream_leader = 1;
            stream_idx = i;
            break;
        }
    }
    bool streaming_bypass = false;
    if (is_stream_leader && stream_idx >= 0) {
        StreamDetect &sd = stream_meta[stream_idx];
        int64_t stride = paddr - sd.last_addr;
        if (sd.last_stride != 0 && stride == sd.last_stride) {
            if (sd.stream_cnt < 7) sd.stream_cnt++;
        } else {
            sd.stream_cnt = 0;
        }
        sd.last_stride = stride;
        sd.last_addr = paddr;
        // If streaming detected and not recently reused, enable bypass
        if (sd.stream_cnt >= 4 && sd.reuse_cnt == 0)
            streaming_bypass = true;
    }

    // --- DIP set-dueling: determine insertion policy ---
    bool use_LIP = false;
    if (std::find(leader_sets_LIP.begin(), leader_sets_LIP.end(), set) != leader_sets_LIP.end())
        use_LIP = true;
    else if (std::find(leader_sets_BIP.begin(), leader_sets_BIP.end(), set) != leader_sets_BIP.end())
        use_LIP = false;
    else
        use_LIP = (PSEL >= 512); // use LIP if PSEL high, BIP if low

    // --- On hit: promote to MRU, clear dead-block bit ---
    if (hit) {
        meta[set][way].rrpv = 0;
        meta[set][way].dead = 0;
        // If in streaming leader set, mark reuse
        if (is_stream_leader && stream_idx >= 0) {
            StreamDetect &sd = stream_meta[stream_idx];
            if (sd.reuse_cnt < 3) sd.reuse_cnt++;
        }
        return;
    }

    // --- Streaming bypass ---
    if (streaming_bypass) {
        // Streaming detected: bypass fill (simulate by marking block as dead)
        meta[set][way].rrpv = 3;
        meta[set][way].dead = 1;
        return;
    }

    // --- DRRIP insertion: SRRIP (most), BRRIP (rare) ---
    uint8_t ins_rrpv = 2; // SRRIP: "long" re-reference
    if (!use_LIP && (rand() % 32 == 0))
        ins_rrpv = 3; // BRRIP: even more distant

    // DIP: if LIP, always insert at LRU
    if (use_LIP)
        ins_rrpv = 3;

    // DIP: if BIP, insert at MRU once every 32 fills
    if (!use_LIP && (rand() % 32 == 0))
        ins_rrpv = 0;

    // Dead-block approximation: if victim was not reused, mark as dead
    if (meta[set][way].dead)
        ins_rrpv = 3; // demote dead blocks

    meta[set][way].rrpv = ins_rrpv;
    meta[set][way].dead = 0; // reset dead on fill

    // DIP: update PSEL for leader sets
    if (std::find(leader_sets_LIP.begin(), leader_sets_LIP.end(), set) != leader_sets_LIP.end()) {
        // If miss, increment PSEL
        if (!hit && PSEL < 1023) PSEL++;
    }
    if (std::find(leader_sets_BIP.begin(), leader_sets_BIP.end(), set) != leader_sets_BIP.end()) {
        // If miss, decrement PSEL
        if (!hit && PSEL > 0) PSEL--;
    }

    // Streaming detector: decay reuse_cnt if no hit
    if (is_stream_leader && stream_idx >= 0 && !hit) {
        StreamDetect &sd = stream_meta[stream_idx];
        if (sd.reuse_cnt > 0) sd.reuse_cnt--;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    uint32_t dead_blocks = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        for (uint32_t w = 0; w < LLC_WAYS; ++w)
            if (meta[s][w].dead) dead_blocks++;
    std::cout << "DSD: dead blocks=" << dead_blocks
              << ", PSEL=" << PSEL << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Periodically decay dead-block bits (every N calls, not implemented here)
    // Could scan meta and set dead=1 for blocks with RRPV==3 and no hit.
}