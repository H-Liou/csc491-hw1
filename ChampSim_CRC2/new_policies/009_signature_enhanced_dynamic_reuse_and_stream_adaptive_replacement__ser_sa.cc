#include <vector>
#include <cstdint>
#include <iostream>
#include <unordered_map>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// RRIP parameters
#define RRIP_MAX 3
#define RRIP_MID 1
#define RRIP_MRU 0

// Signature table parameters
#define SIG_TABLE_SIZE 32 // per-set signature history
#define SIG_REUSE_THRESHOLD 2 // minimum count to consider as reuse

// Helper: Generate a signature from PC and address
inline uint16_t gen_signature(uint64_t PC, uint64_t paddr) {
    // Fold PC and paddr for signature (16 bits)
    return (PC ^ (paddr >> 6)) & 0xFFFF;
}

// Block state
struct BlockState {
    uint8_t rrip;
    uint16_t signature;
};

// Per-set state
struct SetState {
    std::vector<BlockState> blocks;
    // Signature history: signature -> reuse count
    std::unordered_map<uint16_t, uint8_t> sig_table;
    // Stream/reuse counters
    uint32_t recent_reuse;
    uint32_t recent_stream;
    uint8_t mode; // 0:SRRIP, 1:Signature-Reuse, 2:Stream-Adaptive
};

// All sets
std::vector<SetState> sets(LLC_SETS);

// --- Initialize replacement state ---
void InitReplacementState() {
    for (uint32_t s = 0; s < LLC_SETS; ++s) {
        sets[s].blocks.resize(LLC_WAYS);
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            sets[s].blocks[w].rrip = RRIP_MAX;
            sets[s].blocks[w].signature = 0;
        }
        sets[s].sig_table.clear();
        sets[s].recent_reuse = 0;
        sets[s].recent_stream = 0;
        sets[s].mode = 0; // Start in SRRIP mode
    }
}

// --- Find RRIP victim ---
uint32_t FindRRIPVictim(SetState &ss) {
    for (uint32_t loop = 0; loop < 2; ++loop) {
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            if (ss.blocks[w].rrip == RRIP_MAX)
                return w;
        }
        for (uint32_t w = 0; w < LLC_WAYS; ++w)
            if (ss.blocks[w].rrip < RRIP_MAX)
                ss.blocks[w].rrip++;
    }
    return 0;
}

// --- Find Stream victim (BIP-like, prefer oldest RRIP) ---
uint32_t FindStreamVictim(SetState &ss) {
    // Aggressive: prefer blocks with RRIP_MAX, ignore reuse
    return FindRRIPVictim(ss);
}

// --- Find Signature-Reuse victim ---
uint32_t FindSignatureVictim(SetState &ss) {
    // Protect blocks with high reuse signature
    uint32_t victim = LLC_WAYS;
    uint8_t min_rrip = 0;
    for (uint32_t w = 0; w < LLC_WAYS; ++w) {
        uint16_t sig = ss.blocks[w].signature;
        auto it = ss.sig_table.find(sig);
        uint8_t reuse_cnt = (it != ss.sig_table.end()) ? it->second : 0;
        // Prefer to evict blocks with low reuse count and high RRIP
        if ((reuse_cnt < SIG_REUSE_THRESHOLD) && (ss.blocks[w].rrip == RRIP_MAX)) {
            return w;
        }
        // Track block with lowest reuse count and highest RRIP
        if (victim == LLC_WAYS || reuse_cnt < min_rrip) {
            victim = w;
            min_rrip = reuse_cnt;
        }
    }
    // If no clear victim, fallback to RRIP
    return (victim == LLC_WAYS) ? FindRRIPVictim(ss) : victim;
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
    if (ss.mode == 1) // Signature-Reuse phase
        return FindSignatureVictim(ss);
    else if (ss.mode == 2) // Stream-Adaptive phase
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

    // --- Update signature history ---
    auto it = ss.sig_table.find(sig);
    if (hit) {
        ss.sig_table[sig] = std::min<uint8_t>(ss.sig_table[sig] + 1, 15);
        ss.recent_reuse++;
    } else {
        // If table too big, evict oldest
        if (ss.sig_table.size() >= SIG_TABLE_SIZE) {
            // Remove lowest reuse entry
            auto min_it = ss.sig_table.begin();
            for (auto iter = ss.sig_table.begin(); iter != ss.sig_table.end(); ++iter)
                if (iter->second < min_it->second)
                    min_it = iter;
            ss.sig_table.erase(min_it);
        }
        ss.sig_table[sig] = std::min<uint8_t>(ss.sig_table[sig] + 1, 15);
        ss.recent_stream++;
    }

    // --- Phase detection ---
    if ((ss.recent_reuse + ss.recent_stream) >= 64) {
        // If reuse rate > 60%, switch to Signature-Reuse
        if (ss.recent_reuse > 38)
            ss.mode = 1;
        // If stream rate > 75%, switch to Stream-Adaptive
        else if (ss.recent_stream > 48)
            ss.mode = 2;
        // Otherwise, use SRRIP
        else
            ss.mode = 0;
        ss.recent_reuse = 0;
        ss.recent_stream = 0;
    }

    // --- Update block states ---
    ss.blocks[way].signature = sig;
    if (ss.mode == 1) { // Signature-Reuse
        // If signature is hot, promote to MRU
        uint8_t reuse_cnt = ss.sig_table[sig];
        if (reuse_cnt >= SIG_REUSE_THRESHOLD)
            ss.blocks[way].rrip = RRIP_MRU;
        else
            ss.blocks[way].rrip = RRIP_MID;
    }
    else if (ss.mode == 2) { // Stream-Adaptive
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
    // Print mode distribution for first 4 sets
    for (uint32_t s = 0; s < 4; ++s) {
        std::cout << "Set " << s << " mode: ";
        if (sets[s].mode == 0) std::cout << "SRRIP";
        else if (sets[s].mode == 1) std::cout << "Signature-Reuse";
        else std::cout << "Stream-Adaptive";
        std::cout << "\n";
    }
}

// --- Print periodic (heartbeat) statistics ---
void PrintStats_Heartbeat() {
    // No-op
}