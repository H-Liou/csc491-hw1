#include <vector>
#include <cstdint>
#include <iostream>
#include <array>
#include <unordered_map>
#include <algorithm>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

constexpr uint8_t SRRIP_BITS = 2;
constexpr uint8_t SRRIP_MAX = (1 << SRRIP_BITS) - 1; // 3
constexpr uint8_t SRRIP_INSERT = SRRIP_MAX - 1;      // 2

constexpr uint32_t SIG_TABLE_SIZE = 8; // per-set signature table entries
constexpr uint32_t SIG_REUSE_MAX = 7;  // saturating counter max
constexpr uint32_t STRIDE_HISTORY = 4; // stride history length

struct LineMeta {
    uint64_t tag;
    uint8_t rrip;
    uint64_t last_pc;
    uint64_t last_paddr;
};

struct SignatureEntry {
    uint64_t pc;
    uint8_t reuse; // 0 = low, SIG_REUSE_MAX = high
    uint32_t last_used; // LRU for signature table
};

struct SetMeta {
    std::array<SignatureEntry, SIG_TABLE_SIZE> sig_table;
    uint32_t sig_lru_tick;
    std::array<uint64_t, STRIDE_HISTORY> paddr_hist;
    std::array<int64_t, STRIDE_HISTORY-1> stride_hist;
    uint32_t paddr_ptr;
    uint64_t hits, misses, accesses;
};

std::array<std::array<LineMeta, LLC_WAYS>, LLC_SETS> line_meta;
std::array<SetMeta, LLC_SETS> set_meta;
uint64_t global_hits = 0, global_misses = 0;

// --- Helper: Lookup or Insert PC in signature table ---
SignatureEntry* lookup_sig(SetMeta& smeta, uint64_t PC) {
    for (auto& entry : smeta.sig_table) {
        if (entry.pc == PC)
            return &entry;
    }
    // Not found: replace LRU entry
    auto lru_it = std::min_element(
        smeta.sig_table.begin(), smeta.sig_table.end(),
        [](const SignatureEntry& a, const SignatureEntry& b) { return a.last_used < b.last_used; }
    );
    lru_it->pc = PC;
    lru_it->reuse = 1; // start with low reuse
    lru_it->last_used = ++smeta.sig_lru_tick;
    return &(*lru_it);
}

// --- Helper: Detect spatial locality (consistent stride) ---
bool detect_spatial_local(SetMeta& smeta) {
    if (smeta.accesses < STRIDE_HISTORY)
        return false;
    int64_t base_stride = smeta.stride_hist[0];
    for (size_t i = 1; i < smeta.stride_hist.size(); ++i) {
        if (std::abs(smeta.stride_hist[i] - base_stride) > 64)
            return false;
    }
    return true;
}

// Initialize replacement state
void InitReplacementState() {
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            line_meta[set][way] = {0, SRRIP_MAX, 0, 0};
        }
        for (auto& entry : set_meta[set].sig_table) {
            entry.pc = 0; entry.reuse = 1; entry.last_used = 0;
        }
        set_meta[set].sig_lru_tick = 0;
        set_meta[set].paddr_hist.fill(0);
        set_meta[set].stride_hist.fill(0);
        set_meta[set].paddr_ptr = 0;
        set_meta[set].hits = set_meta[set].misses = set_meta[set].accesses = 0;
    }
    global_hits = global_misses = 0;
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
    // Prefer lines with highest RRIP, then lowest signature reuse, then lowest spatial locality
    uint8_t max_rrip = 0;
    for (uint32_t w = 0; w < LLC_WAYS; ++w)
        if (line_meta[set][w].rrip > max_rrip)
            max_rrip = line_meta[set][w].rrip;

    uint32_t victim = 0;
    uint8_t min_reuse = SIG_REUSE_MAX + 1;
    bool spatial_local = detect_spatial_local(set_meta[set]);

    for (uint32_t w = 0; w < LLC_WAYS; ++w) {
        if (line_meta[set][w].rrip == max_rrip) {
            // Lookup signature reuse for last_pc
            SignatureEntry* sig = lookup_sig(set_meta[set], line_meta[set][w].last_pc);
            uint8_t reuse = sig ? sig->reuse : 1;
            // Prefer lowest reuse, and if spatial locality is low, prefer those with mismatched stride
            bool stride_match = false;
            if (spatial_local && set_meta[set].accesses >= STRIDE_HISTORY) {
                int64_t stride = int64_t(line_meta[set][w].last_paddr) - int64_t(set_meta[set].paddr_hist[(set_meta[set].paddr_ptr+STRIDE_HISTORY-1)%STRIDE_HISTORY]);
                stride_match = std::abs(stride - set_meta[set].stride_hist[0]) <= 64;
            }
            if ((reuse < min_reuse) || (reuse == min_reuse && !stride_match)) {
                min_reuse = reuse;
                victim = w;
            }
        }
    }
    return victim;
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
    global_hits += hit;
    global_misses += !hit;
    auto& smeta = set_meta[set];
    smeta.accesses++;
    smeta.hits += hit;
    smeta.misses += !hit;

    // Update stride history for spatial locality
    uint32_t prev_idx = (smeta.paddr_ptr + STRIDE_HISTORY - 1) % STRIDE_HISTORY;
    uint64_t prev_paddr = smeta.paddr_hist[prev_idx];
    int64_t stride = int64_t(paddr) - int64_t(prev_paddr);
    if (smeta.paddr_ptr > 0)
        smeta.stride_hist[smeta.paddr_ptr - 1] = stride;
    smeta.paddr_hist[smeta.paddr_ptr] = paddr;
    smeta.paddr_ptr = (smeta.paddr_ptr + 1) % STRIDE_HISTORY;

    // Update signature table for PC
    SignatureEntry* sig = lookup_sig(smeta, PC);
    sig->last_used = ++smeta.sig_lru_tick;
    if (hit)
        sig->reuse = std::min(sig->reuse + 1, SIG_REUSE_MAX);
    else
        sig->reuse = std::max(sig->reuse - 1, 1u);

    // Update per-line metadata
    auto& lmeta = line_meta[set][way];
    lmeta.tag = paddr >> 6;
    lmeta.last_pc = PC;
    lmeta.last_paddr = paddr;

    // Insertion/promotion policy
    bool spatial_local = detect_spatial_local(smeta);
    if (hit) {
        lmeta.rrip = 0; // Promote on hit
    } else {
        // If signature reuse is high, or spatial locality detected, insert with low RRIP
        if ((sig && sig->reuse >= SIG_REUSE_MAX-1) || spatial_local)
            lmeta.rrip = 0;
        else if (sig && sig->reuse >= SIG_REUSE_MAX/2)
            lmeta.rrip = 1;
        else
            lmeta.rrip = SRRIP_INSERT;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "DSRLR Policy: Total Hits = " << global_hits
              << ", Total Misses = " << global_misses << std::endl;
    std::cout << "Hit Rate = "
              << (100.0 * global_hits / (global_hits + global_misses)) << "%" << std::endl;
    // Print signature table reuse distribution for set 0
    std::cout << "Signature Table (Set 0) PC Reuse Counters:\n";
    for (const auto& entry : set_meta[0].sig_table)
        std::cout << "PC: 0x" << std::hex << entry.pc << std::dec
                  << ", Reuse: " << int(entry.reuse) << "\n";
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    std::cout << "[DSRLR Heartbeat] Hits: " << global_hits
              << ", Misses: " << global_misses << std::endl;
    std::cout << "[Set 0] Accesses: " << set_meta[0].accesses
              << ", Hits: " << set_meta[0].hits
              << ", Misses: " << set_meta[0].misses << std::endl;
}