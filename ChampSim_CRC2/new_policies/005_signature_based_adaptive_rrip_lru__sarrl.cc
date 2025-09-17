#include <vector>
#include <unordered_map>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// RRIP constants
#define MAX_RRPV 3
#define LONG_RRPV 3
#define SHORT_RRPV 1

// Signature table parameters
#define SIG_TABLE_SIZE 256 // Per-set, small table
#define SIG_HIT_THRESHOLD 4 // If hit count >= threshold, treat as high reuse

struct SigEntry {
    uint64_t pc_sig; // Lower bits of PC
    uint16_t hit_count;
    uint16_t access_count;
};

struct SetState {
    uint8_t rrpv[LLC_WAYS];
    // Signature table: circular buffer
    std::vector<SigEntry> sig_table;
    uint32_t sig_head;
};

std::vector<SetState> sets(LLC_SETS);

// Helper: find or insert PC signature in table, returns index
uint32_t find_or_insert_sig(std::vector<SigEntry>& table, uint32_t& head, uint64_t pc_sig) {
    for (uint32_t i = 0; i < table.size(); ++i) {
        if (table[i].pc_sig == pc_sig)
            return i;
    }
    // Not found, insert at head (replace oldest)
    if (table.size() < SIG_TABLE_SIZE) {
        table.push_back({pc_sig, 0, 0});
        return table.size() - 1;
    } else {
        table[head] = {pc_sig, 0, 0};
        uint32_t idx = head;
        head = (head + 1) % SIG_TABLE_SIZE;
        return idx;
    }
}

// Initialize replacement state
void InitReplacementState() {
    for (uint32_t s = 0; s < LLC_SETS; ++s) {
        for (uint32_t w = 0; w < LLC_WAYS; ++w)
            sets[s].rrpv[w] = LONG_RRPV;
        sets[s].sig_table.clear();
        sets[s].sig_head = 0;
    }
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
    SetState &ss = sets[set];
    while (true) {
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            if (ss.rrpv[w] == MAX_RRPV)
                return w;
        }
        // Increment all RRPVs (aging)
        for (uint32_t w = 0; w < LLC_WAYS; ++w)
            if (ss.rrpv[w] < MAX_RRPV)
                ss.rrpv[w]++;
    }
    return 0; // Should not happen
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
    SetState &ss = sets[set];
    uint64_t pc_sig = PC & 0xFFF; // Use lower 12 bits as signature
    uint32_t sig_idx = find_or_insert_sig(ss.sig_table, ss.sig_head, pc_sig);
    SigEntry &sig = ss.sig_table[sig_idx];
    sig.access_count++;
    if (hit)
        sig.hit_count++;

    // If hit, always promote to MRU (RRPV=0)
    if (hit)
        ss.rrpv[way] = 0;
    else {
        // If signature shows frequent reuse, insert with SHORT_RRPV (LRU-like)
        if (sig.hit_count >= SIG_HIT_THRESHOLD && sig.access_count > SIG_HIT_THRESHOLD) {
            ss.rrpv[way] = SHORT_RRPV;
        } else {
            // Otherwise, insert with LONG_RRPV (RRIP streaming/irregular)
            ss.rrpv[way] = LONG_RRPV;
        }
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    // Optionally, print signature table stats for a few sets
    for (uint32_t s = 0; s < 4; ++s) {
        std::cout << "Set " << s << " Signature Table:\n";
        for (auto &sig : sets[s].sig_table) {
            std::cout << "PC_sig=" << std::hex << sig.pc_sig << std::dec
                      << " hits=" << sig.hit_count << " acc=" << sig.access_count << "\n";
        }
    }
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // No-op for now
}