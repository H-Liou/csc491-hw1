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
#define RRIP_MID 1
#define RRIP_MRU 0

// Signature table parameters
#define SIG_TABLE_SIZE 16 // per-set signature history
#define SIG_REUSE_THRESHOLD 2 // minimum count to consider as reuse

// Stride detector parameters
#define STRIDE_WINDOW 8
#define STRIDE_MATCH_THRESHOLD 6

// Phase classifier window
#define PHASE_WINDOW 64

// Helper: Generate a signature from PC and address
inline uint16_t gen_signature(uint64_t PC, uint64_t paddr) {
    return (PC ^ (paddr >> 6)) & 0xFFFF;
}

// Block state
struct BlockState {
    uint8_t rrip;
    uint16_t signature;
    uint64_t tag;
};

// Per-set state
struct SetState {
    std::vector<BlockState> blocks;
    // Signature history: signature -> reuse count
    std::unordered_map<uint16_t, uint8_t> sig_table;
    // Stride detection
    std::vector<int64_t> stride_hist;
    uint64_t last_addr;
    // Phase classifier
    uint32_t hit_count;
    uint32_t miss_count;
    uint32_t stream_count;
    uint32_t reuse_count;
    uint8_t phase; // 0:SRRIP, 1:Signature-Reuse, 2:Spatial-Stream
};

std::vector<SetState> sets(LLC_SETS);

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
        sets[s].hit_count = 0;
        sets[s].miss_count = 0;
        sets[s].stream_count = 0;
        sets[s].reuse_count = 0;
        sets[s].phase = 0; // Start in SRRIP phase
    }
}

// --- Find RRIP victim ---
uint32_t FindRRIPVictim(SetState &ss) {
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

// --- Find Signature-Reuse victim ---
uint32_t FindSignatureVictim(SetState &ss) {
    uint32_t victim = LLC_WAYS;
    uint8_t min_reuse = 255;
    for (uint32_t w = 0; w < LLC_WAYS; ++w) {
        uint16_t sig = ss.blocks[w].signature;
        auto it = ss.sig_table.find(sig);
        uint8_t reuse_cnt = (it != ss.sig_table.end()) ? it->second : 0;
        if ((reuse_cnt < SIG_REUSE_THRESHOLD) && (ss.blocks[w].rrip == RRIP_MAX))
            return w;
        if (victim == LLC_WAYS || reuse_cnt < min_reuse) {
            victim = w;
            min_reuse = reuse_cnt;
        }
    }
    return (victim == LLC_WAYS) ? FindRRIPVictim(ss) : victim;
}

// --- Find Spatial-Stream victim ---
uint32_t FindStreamVictim(SetState &ss) {
    // Prefer oldest RRIP, but if stride detected, evict block with lowest reuse count
    int64_t common_stride = 0;
    if (ss.stride_hist.size() >= STRIDE_MATCH_THRESHOLD) {
        std::vector<int64_t> sorted_strides = ss.stride_hist;
        std::sort(sorted_strides.begin(), sorted_strides.end());
        common_stride = sorted_strides[sorted_strides.size()/2];
    }
    // If stride detected, evict block whose tag is furthest from last_addr
    if (std::abs(common_stride) > 0) {
        uint32_t victim = 0;
        uint64_t max_dist = 0;
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            uint64_t dist = std::abs((int64_t)ss.blocks[w].tag - (int64_t)ss.last_addr);
            if (dist > max_dist) {
                max_dist = dist;
                victim = w;
            }
        }
        return victim;
    }
    // Otherwise, fallback to RRIP
    return FindRRIPVictim(ss);
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
    if (ss.phase == 1) // Signature-Reuse phase
        return FindSignatureVictim(ss);
    else if (ss.phase == 2) // Spatial-Stream phase
        return FindStreamVictim(ss);
    else // SRRIP phase
        return FindRRIPVictim(ss);
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
        ss.reuse_count++;
        ss.hit_count++;
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
        ss.miss_count++;
    }

    // --- Stream detection ---
    if (std::abs(stride) > 0 && ss.stride_hist.size() >= STRIDE_MATCH_THRESHOLD) {
        // If most strides match, treat as streaming
        int64_t common_stride = stride;
        int match = std::count(ss.stride_hist.begin(), ss.stride_hist.end(), common_stride);
        if (match >= STRIDE_MATCH_THRESHOLD)
            ss.stream_count++;
    }

    // --- Phase detection ---
    if ((ss.hit_count + ss.miss_count) >= PHASE_WINDOW) {
        // If stream rate > 60%, switch to Spatial-Stream
        if (ss.stream_count > (PHASE_WINDOW * 0.6))
            ss.phase = 2;
        // If reuse rate > 40%, switch to Signature-Reuse
        else if (ss.reuse_count > (PHASE_WINDOW * 0.4))
            ss.phase = 1;
        else
            ss.phase = 0; // Default SRRIP
        ss.hit_count = 0;
        ss.miss_count = 0;
        ss.stream_count = 0;
        ss.reuse_count = 0;
    }

    // --- Update block states ---
    ss.blocks[way].signature = sig;
    ss.blocks[way].tag = paddr;
    if (ss.phase == 1) { // Signature-Reuse
        uint8_t reuse_cnt = ss.sig_table[sig];
        if (reuse_cnt >= SIG_REUSE_THRESHOLD)
            ss.blocks[way].rrip = RRIP_MRU;
        else
            ss.blocks[way].rrip = RRIP_MID;
    }
    else if (ss.phase == 2) { // Spatial-Stream
        // Insert with RRIP_MAX (low priority) 95% of time, RRIP_MRU 5% of time
        static uint32_t bip_counter = 0;
        if (!hit) {
            bip_counter++;
            if (bip_counter % 20 == 0)
                ss.blocks[way].rrip = RRIP_MRU;
            else
                ss.blocks[way].rrip = RRIP_MAX;
        } else {
            ss.blocks[way].rrip = RRIP_MRU;
        }
    }
    else { // SRRIP
        if (hit)
            ss.blocks[way].rrip = RRIP_MRU;
        else
            ss.blocks[way].rrip = RRIP_MID;
    }
}

// --- Print end-of-simulation statistics ---
void PrintStats() {
    // Print phase distribution for first 4 sets
    for (uint32_t s = 0; s < 4; ++s) {
        std::cout << "Set " << s << " phase: ";
        if (sets[s].phase == 0) std::cout << "SRRIP";
        else if (sets[s].phase == 1) std::cout << "Signature-Reuse";
        else std::cout << "Spatial-Stream";
        std::cout << "\n";
    }
}

// --- Print periodic (heartbeat) statistics ---
void PrintStats_Heartbeat() {
    // No-op
}