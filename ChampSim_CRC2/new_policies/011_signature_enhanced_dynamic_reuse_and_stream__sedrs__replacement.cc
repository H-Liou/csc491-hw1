#include <vector>
#include <cstdint>
#include <iostream>
#include <unordered_map>
#include <algorithm>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// RRIP parameters
#define RRIP_MAX 3
#define RRIP_MID 2
#define RRIP_MRU 0

// Signature table parameters
#define SIG_TABLE_SIZE 8 // per-set signature history
#define SIG_REUSE_THRESHOLD 2 // minimum count to consider as reuse

// Stride detector parameters
#define STRIDE_WINDOW 8
#define STRIDE_MATCH_THRESHOLD 6

// Block state
struct BlockState {
    uint8_t rrip;
    uint16_t signature;
    uint64_t tag;
};

// Per-set state
struct SetState {
    std::vector<BlockState> blocks;
    std::unordered_map<uint16_t, uint8_t> sig_table; // signature -> reuse count
    std::vector<int64_t> stride_hist;
    uint64_t last_addr;
    uint32_t bip_counter;
};

std::vector<SetState> sets(LLC_SETS);

// Helper: Generate a signature from PC and address
inline uint16_t gen_signature(uint64_t PC, uint64_t paddr) {
    return (PC ^ (paddr >> 6)) & 0xFFFF;
}

// --- Initialize replacement state ---
void InitReplacementState() {
    for (uint32_t s = 0; s < LLC_SETS; ++s) {
        sets[s].blocks.resize(LLC_WAYS);
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            sets[s].blocks[w].rrip = RRIP_MAX;
            sets[s].blocks[w].signature = 0;
            sets[s].blocks[w].tag = 0;
        }
        sets[s].sig_table.clear();
        sets[s].stride_hist.clear();
        sets[s].last_addr = 0;
        sets[s].bip_counter = 0;
    }
}

// --- Find victim in the set ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    SetState &ss = sets[set];

    // Detect streaming: check stride history
    int64_t stride = (ss.last_addr == 0) ? 0 : (int64_t)paddr - (int64_t)ss.last_addr;
    int stride_matches = 0;
    if (stride != 0 && ss.stride_hist.size() >= STRIDE_MATCH_THRESHOLD) {
        stride_matches = std::count(ss.stride_hist.begin(), ss.stride_hist.end(), stride);
    }
    bool is_streaming = (stride_matches >= STRIDE_MATCH_THRESHOLD);

    // Prefer eviction of blocks with low signature reuse and/or stream-like blocks
    uint32_t victim = LLC_WAYS;
    uint8_t min_reuse = 255;
    for (uint32_t w = 0; w < LLC_WAYS; ++w) {
        uint16_t sig = ss.blocks[w].signature;
        auto it = ss.sig_table.find(sig);
        uint8_t reuse_cnt = (it != ss.sig_table.end()) ? it->second : 0;
        // If streaming, prefer blocks with low reuse or furthest tag from last_addr
        if (is_streaming) {
            uint64_t dist = std::abs((int64_t)ss.blocks[w].tag - (int64_t)ss.last_addr);
            if (reuse_cnt < SIG_REUSE_THRESHOLD) {
                if (victim == LLC_WAYS || dist > std::abs((int64_t)ss.blocks[victim].tag - (int64_t)ss.last_addr)) {
                    victim = w;
                    min_reuse = reuse_cnt;
                }
            }
        } else {
            // Non-stream: prefer lowest reuse count among RRIP_MAX blocks
            if ((reuse_cnt < SIG_REUSE_THRESHOLD) && (ss.blocks[w].rrip == RRIP_MAX)) {
                return w;
            }
            if (victim == LLC_WAYS || reuse_cnt < min_reuse) {
                victim = w;
                min_reuse = reuse_cnt;
            }
        }
    }
    // Fallback: RRIP victim
    if (victim == LLC_WAYS) {
        // Standard RRIP: select first RRIP_MAX, else increment all and repeat
        for (uint32_t loop = 0; loop < 2; ++loop) {
            for (uint32_t w = 0; w < LLC_WAYS; ++w)
                if (ss.blocks[w].rrip == RRIP_MAX)
                    return w;
            for (uint32_t w = 0; w < LLC_WAYS; ++w)
                if (ss.blocks[w].rrip < RRIP_MAX)
                    ss.blocks[w].rrip++;
        }
        return 0;
    }
    return victim;
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
    SetState &ss = sets[set];
    uint16_t sig = gen_signature(PC, paddr);

    // --- Update stride history ---
    int64_t stride = (ss.last_addr == 0) ? 0 : (int64_t)paddr - (int64_t)ss.last_addr;
    if (stride != 0) {
        ss.stride_hist.push_back(stride);
        if (ss.stride_hist.size() > STRIDE_WINDOW)
            ss.stride_hist.erase(ss.stride_hist.begin());
    }
    ss.last_addr = paddr;

    // --- Update signature table ---
    auto it = ss.sig_table.find(sig);
    if (hit) {
        ss.sig_table[sig] = std::min<uint8_t>(ss.sig_table[sig] + 1, 15);
    } else {
        if (ss.sig_table.size() >= SIG_TABLE_SIZE) {
            // Remove lowest reuse entry
            auto min_it = ss.sig_table.begin();
            for (auto iter = ss.sig_table.begin(); iter != ss.sig_table.end(); ++iter)
                if (iter->second < min_it->second)
                    min_it = iter;
            ss.sig_table.erase(min_it);
        }
        ss.sig_table[sig] = 1;
    }

    // --- Streaming detection for insertion policy ---
    int stride_matches = 0;
    if (stride != 0 && ss.stride_hist.size() >= STRIDE_MATCH_THRESHOLD) {
        stride_matches = std::count(ss.stride_hist.begin(), ss.stride_hist.end(), stride);
    }
    bool is_streaming = (stride_matches >= STRIDE_MATCH_THRESHOLD);

    // --- Update block states ---
    ss.blocks[way].signature = sig;
    ss.blocks[way].tag = paddr;

    if (is_streaming) {
        // Streaming: insert at RRIP_MAX most of the time, RRIP_MRU occasionally (BIP-like)
        if (!hit) {
            ss.bip_counter++;
            if (ss.bip_counter % 32 == 0)
                ss.blocks[way].rrip = RRIP_MRU;
            else
                ss.blocks[way].rrip = RRIP_MAX;
        } else {
            ss.blocks[way].rrip = RRIP_MRU;
        }
    } else {
        // Non-stream: protect blocks with high signature reuse
        uint8_t reuse_cnt = ss.sig_table[sig];
        if (reuse_cnt >= SIG_REUSE_THRESHOLD)
            ss.blocks[way].rrip = RRIP_MRU;
        else
            ss.blocks[way].rrip = RRIP_MID;
    }
}

// --- Print end-of-simulation statistics ---
void PrintStats() {
    // Print signature table size and stride history for first 4 sets
    for (uint32_t s = 0; s < 4; ++s) {
        std::cout << "Set " << s << " sig_table size: " << sets[s].sig_table.size()
                  << ", stride_hist size: " << sets[s].stride_hist.size() << "\n";
    }
}

// --- Print periodic (heartbeat) statistics ---
void PrintStats_Heartbeat() {
    // No-op
}