#include <vector>
#include <cstdint>
#include <iostream>
#include <array>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- SRRIP parameters ---
constexpr uint8_t SRRIP_BITS = 2;
constexpr uint8_t SRRIP_MAX = (1 << SRRIP_BITS) - 1; // 3
constexpr uint8_t SRRIP_INSERT = SRRIP_MAX - 1;      // 2

// --- BIP parameters ---
constexpr uint32_t BIP_PROB = 32; // 1/32 lines inserted with high priority

// --- Policy selection ---
enum PolicyType { POLICY_SRRIP = 0, POLICY_BIP = 1 };

// --- Per-line metadata ---
struct LineMeta {
    uint64_t tag;
    uint8_t rrip;
};

// --- Per-set metadata ---
struct SetMeta {
    PolicyType policy;
    // Per-policy stats for this set
    uint64_t srrip_hits, srrip_accesses;
    uint64_t bip_hits, bip_accesses;
    uint64_t last_switch_access;
};

// Global stats
uint64_t global_hits = 0, global_misses = 0;
std::array<std::array<LineMeta, LLC_WAYS>, LLC_SETS> line_meta;
std::array<SetMeta, LLC_SETS> set_meta;

// Initialize replacement state
void InitReplacementState() {
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            line_meta[set][way] = {0, SRRIP_MAX};
        }
        set_meta[set].policy = POLICY_SRRIP;
        set_meta[set].srrip_hits = set_meta[set].srrip_accesses = 0;
        set_meta[set].bip_hits = set_meta[set].bip_accesses = 0;
        set_meta[set].last_switch_access = 0;
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
    // SRRIP/BIP both use RRIP stack for victim selection
    while (true) {
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            if (line_meta[set][w].rrip == SRRIP_MAX)
                return w;
        }
        for (uint32_t w = 0; w < LLC_WAYS; ++w)
            if (line_meta[set][w].rrip < SRRIP_MAX)
                line_meta[set][w].rrip++;
    }
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
    PolicyType policy = set_meta[set].policy;

    // Update global stats
    if (hit) global_hits++; else global_misses++;

    // Update per-set stats
    if (policy == POLICY_SRRIP) {
        set_meta[set].srrip_accesses++;
        if (hit) set_meta[set].srrip_hits++;
    } else { // POLICY_BIP
        set_meta[set].bip_accesses++;
        if (hit) set_meta[set].bip_hits++;
    }

    // Per-set adaptation: every 2048 accesses, switch to the better policy for this set
    uint64_t total_access = set_meta[set].srrip_accesses + set_meta[set].bip_accesses;
    if (total_access - set_meta[set].last_switch_access >= 2048) {
        double srrip_rate = set_meta[set].srrip_accesses ? (double)set_meta[set].srrip_hits / set_meta[set].srrip_accesses : 0.0;
        double bip_rate   = set_meta[set].bip_accesses   ? (double)set_meta[set].bip_hits   / set_meta[set].bip_accesses   : 0.0;
        set_meta[set].policy = (srrip_rate >= bip_rate) ? POLICY_SRRIP : POLICY_BIP;
        set_meta[set].last_switch_access = total_access;
        // Optionally, reset stats to avoid stale data
        set_meta[set].srrip_hits = set_meta[set].srrip_accesses = 0;
        set_meta[set].bip_hits = set_meta[set].bip_accesses = 0;
    }

    // Update per-line metadata
    if (policy == POLICY_SRRIP) {
        if (hit) {
            line_meta[set][way].rrip = 0; // Promote on hit
            line_meta[set][way].tag = paddr >> 6;
        } else {
            line_meta[set][way].rrip = SRRIP_INSERT; // Insert at SRRIP_INSERT (2)
            line_meta[set][way].tag = paddr >> 6;
        }
    } else { // POLICY_BIP
        if (hit) {
            line_meta[set][way].rrip = 0; // Promote on hit
            line_meta[set][way].tag = paddr >> 6;
        } else {
            // BIP: insert with RRIP_MAX except for 1/BIP_PROB of misses
            static uint32_t bip_counter = 0;
            bip_counter++;
            if (bip_counter % BIP_PROB == 0) {
                line_meta[set][way].rrip = SRRIP_INSERT; // Insert with SRRIP_INSERT (2)
            } else {
                line_meta[set][way].rrip = SRRIP_MAX; // Insert with low priority
            }
            line_meta[set][way].tag = paddr >> 6;
        }
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "DSRRIP-BIP-PSAD Policy: Total Hits = " << global_hits
              << ", Total Misses = " << global_misses << std::endl;
    std::cout << "Hit Rate = "
              << (100.0 * global_hits / (global_hits + global_misses)) << "%" << std::endl;

    // Print per-policy hit rates (average across sets)
    double srrip_sum = 0, bip_sum = 0;
    int srrip_sets = 0, bip_sets = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        if (set_meta[set].policy == POLICY_SRRIP) {
            srrip_sum += set_meta[set].srrip_accesses ? (100.0 * set_meta[set].srrip_hits / set_meta[set].srrip_accesses) : 0.0;
            srrip_sets++;
        } else {
            bip_sum += set_meta[set].bip_accesses ? (100.0 * set_meta[set].bip_hits / set_meta[set].bip_accesses) : 0.0;
            bip_sets++;
        }
    }
    std::cout << "Avg SRRIP Set Hit Rate: " << (srrip_sets ? srrip_sum / srrip_sets : 0.0) << "%" << std::endl;
    std::cout << "Avg BIP Set Hit Rate: " << (bip_sets ? bip_sum / bip_sets : 0.0) << "%" << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    std::cout << "[DSRRIP-BIP-PSAD Heartbeat] Hits: " << global_hits
              << ", Misses: " << global_misses << std::endl;
    // Print a sample set's stats
    uint32_t sample_set = 0;
    std::cout << "[Set " << sample_set << "] Policy: " << (set_meta[sample_set].policy == POLICY_SRRIP ? "SRRIP" : "BIP")
              << ", SRRIP Hits: " << set_meta[sample_set].srrip_hits
              << ", SRRIP Accesses: " << set_meta[sample_set].srrip_accesses
              << ", BIP Hits: " << set_meta[sample_set].bip_hits
              << ", BIP Accesses: " << set_meta[sample_set].bip_accesses << std::endl;
}