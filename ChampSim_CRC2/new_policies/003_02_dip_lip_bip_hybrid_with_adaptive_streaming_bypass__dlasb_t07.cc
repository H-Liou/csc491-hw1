#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16
#define DIP_LEADER_SETS 64  // 64 leader sets for DIP (~3%)

struct DLASB_BlockMeta {
    uint8_t rrpv;      // 2 bits
    uint8_t dead;      // 1 bit (dead block flag)
};
DLASB_BlockMeta block_meta[LLC_SETS][LLC_WAYS];

// DIP: PSEL counter and leader set bookkeeping
uint16_t dip_psel = 512; // 10 bits, init neutral
uint8_t dip_leader_type[LLC_SETS]; // 0: LIP, 1: BIP, 2: follower

// Per-leader-set hit count for LIP/BIP
uint64_t dip_lip_hits = 0;
uint64_t dip_bip_hits = 0;

// Streaming detector: 3 bits/set
struct DLASB_StreamSet {
    uint64_t last_addr;
    uint8_t stride_count; // up to 3
    uint8_t streaming;    // 1 if streaming detected
    uint8_t window;       // streaming window countdown
};
DLASB_StreamSet stream_sets[LLC_SETS];

// RRIP constants
const uint8_t RRIP_MAX = 3;
const uint8_t RRIP_MRU = 0;
const uint8_t RRIP_DISTANT = 2;

// Streaming window length
const uint8_t STREAM_WIN = 8;

// DIP: BIP probability (1/32 inserts at MRU)
const uint8_t BIP_PROB = 32;

// Stats
uint64_t access_counter = 0;

void InitReplacementState() {
    memset(block_meta, 0, sizeof(block_meta));
    memset(stream_sets, 0, sizeof(stream_sets));
    dip_psel = 512;
    dip_lip_hits = 0;
    dip_bip_hits = 0;
    // Assign leader sets: round-robin, 32 LIP, 32 BIP, rest followers
    for (uint32_t s = 0; s < LLC_SETS; ++s) {
        if (s < DIP_LEADER_SETS/2)
            dip_leader_type[s] = 0; // LIP
        else if (s < DIP_LEADER_SETS)
            dip_leader_type[s] = 1; // BIP
        else
            dip_leader_type[s] = 2; // follower
    }
    access_counter = 0;
}

uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Streaming active? Evict any block with dead==1, else LRU
    if (stream_sets[set].streaming && stream_sets[set].window > 0) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (block_meta[set][way].dead == 1)
                return way;
        // Else evict block with RRPV==RRIP_MAX
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (block_meta[set][way].rrpv == RRIP_MAX)
                return way;
        // Increment RRPVs if needed (standard SRRIP)
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (block_meta[set][way].rrpv < RRIP_MAX)
                block_meta[set][way].rrpv++;
        // Retry
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (block_meta[set][way].rrpv == RRIP_MAX)
                return way;
        return 0;
    }
    // Non-streaming: prefer dead blocks, else SRRIP
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (block_meta[set][way].dead == 1)
            return way;
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (block_meta[set][way].rrpv == RRIP_MAX)
            return way;
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (block_meta[set][way].rrpv < RRIP_MAX)
            block_meta[set][way].rrpv++;
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (block_meta[set][way].rrpv == RRIP_MAX)
            return way;
    return 0;
}

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
    access_counter++;
    // --- Streaming detector ---
    DLASB_StreamSet &ss = stream_sets[set];
    uint64_t cur_addr = paddr >> 6;
    int64_t stride = cur_addr - ss.last_addr;
    if (ss.last_addr != 0 && (stride == 1 || stride == -1)) {
        if (ss.stride_count < 3) ss.stride_count++;
        if (ss.stride_count == 3 && !ss.streaming) {
            ss.streaming = 1;
            ss.window = STREAM_WIN;
        }
    } else {
        ss.stride_count = 0;
        ss.streaming = 0;
        ss.window = 0;
    }
    ss.last_addr = cur_addr;
    if (ss.streaming && ss.window > 0)
        ss.window--;

    // --- DIP leader/follower logic ---
    bool use_lip = false, use_bip = false;
    if (dip_leader_type[set] == 0) use_lip = true;
    else if (dip_leader_type[set] == 1) use_bip = true;
    else use_lip = (dip_psel >= 512); // follower: majority

    // --- On hit ---
    if (hit) {
        block_meta[set][way].rrpv = RRIP_MRU;
        block_meta[set][way].dead = 0;
        // DIP bookkeeping
        if (dip_leader_type[set] == 0) dip_lip_hits++;
        else if (dip_leader_type[set] == 1) dip_bip_hits++;
    }
    // --- On miss (new insertion) ---
    else {
        // Streaming active? Insert at LRU, mark dead
        if (ss.streaming && ss.window > 0) {
            block_meta[set][way].rrpv = RRIP_MAX;
            block_meta[set][way].dead = 1;
        } else {
            // DIP insertion logic
            if (use_lip) {
                block_meta[set][way].rrpv = RRIP_MAX;
                block_meta[set][way].dead = 0;
            } else if (use_bip) {
                // Insert at MRU 1/BIP_PROB of the time, else at LRU
                if ((access_counter % BIP_PROB) == 0) {
                    block_meta[set][way].rrpv = RRIP_MRU;
                    block_meta[set][way].dead = 0;
                } else {
                    block_meta[set][way].rrpv = RRIP_MAX;
                    block_meta[set][way].dead = 0;
                }
            } else {
                // Follower: majority policy (LIP/BIP via PSEL)
                if (dip_psel >= 512) {
                    block_meta[set][way].rrpv = RRIP_MAX;
                    block_meta[set][way].dead = 0;
                } else {
                    if ((access_counter % BIP_PROB) == 0) {
                        block_meta[set][way].rrpv = RRIP_MRU;
                        block_meta[set][way].dead = 0;
                    } else {
                        block_meta[set][way].rrpv = RRIP_MAX;
                        block_meta[set][way].dead = 0;
                    }
                }
            }
        }
        // DIP PSEL update every so often (every 4096 misses)
        if (access_counter % 4096 == 0) {
            if (dip_lip_hits > dip_bip_hits && dip_psel < 1023)
                dip_psel++;
            else if (dip_bip_hits > dip_lip_hits && dip_psel > 0)
                dip_psel--;
            dip_lip_hits = 0;
            dip_bip_hits = 0;
        }
    }
}

void PrintStats() {
    // Streaming set count
    uint64_t streaming_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (stream_sets[s].streaming)
            streaming_sets++;
    std::cout << "DLASB: Streaming sets at end: " << streaming_sets << std::endl;

    // Dead block fraction
    uint64_t dead_blocks = 0, total_blocks = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            if (block_meta[s][w].dead == 1)
                dead_blocks++;
            total_blocks++;
        }
    std::cout << "DLASB: Fraction of dead blocks at end: " << (double(dead_blocks) / total_blocks) << std::endl;

    std::cout << "DLASB: DIP PSEL at end: " << dip_psel << std::endl;
}

void PrintStats_Heartbeat() {
    // Optionally print streaming window stats or dead block ratio
    // For brevity, print streaming sets every 10M accesses
    if ((access_counter % 10000000) == 0) {
        uint64_t streaming_sets = 0;
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            if (stream_sets[s].streaming)
                streaming_sets++;
        std::cout << "[DLASB Heartbeat] Streaming sets: " << streaming_sets << std::endl;
    }
}