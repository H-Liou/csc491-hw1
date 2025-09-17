#include <vector>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"
#include <unordered_map>
#include <algorithm>

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// Metadata parameters
#define SHIP_SIGNATURE_BITS 6
#define SHIP_SIGNATURE_COUNT (1 << SHIP_SIGNATURE_BITS)
#define SHIP_COUNTER_BITS 2

#define DIP_LEADER_SETS 64
#define DIP_PSEL_BITS 10
#define STREAM_DETECT_WINDOW 8
#define STREAM_DELTA_THRESHOLD 6
#define STREAM_BYPASS_RRPV 3

// Replacement state structures
struct SHIPEntry {
    uint8_t counter; // 2 bits
};

SHIPEntry ship_table[SHIP_SIGNATURE_COUNT];
uint16_t line_signature[LLC_SETS][LLC_WAYS] = {}; // Per-line PC signature
uint8_t rrpv[LLC_SETS][LLC_WAYS] = {}; // 2-bit RRPV
uint16_t last_addr[LLC_SETS] = {};     // For streaming detection
uint8_t stream_window[LLC_SETS] = {};  // Count monotonic accesses in window

// DIP insertion control
uint16_t dip_psel = 1 << (DIP_PSEL_BITS - 1);
bool is_lip_leader(uint32_t set) { return set < DIP_LEADER_SETS; }
bool is_bip_leader(uint32_t set) { return set >= LLC_SETS - DIP_LEADER_SETS; }
bool use_lip() { return dip_psel >= (1 << (DIP_PSEL_BITS - 1)); }

// Initialize replacement state
void InitReplacementState() {
    std::fill(&rrpv[0][0], &rrpv[0][0] + LLC_SETS * LLC_WAYS, 3);
    std::fill(&line_signature[0][0], &line_signature[0][0] + LLC_SETS * LLC_WAYS, 0);
    std::fill(&ship_table[0], &ship_table[0] + SHIP_SIGNATURE_COUNT, SHIPEntry{1});
    std::fill(&last_addr[0], &last_addr[0] + LLC_SETS, 0);
    std::fill(&stream_window[0], &stream_window[0] + LLC_SETS, 0);
    dip_psel = 1 << (DIP_PSEL_BITS - 1);
}

// Streaming detector: return true if (STREAM_DELTA_THRESHOLD) out of last (STREAM_DETECT_WINDOW) accesses are monotonic
bool is_streaming(uint32_t set, uint64_t paddr) {
    uint64_t addr = paddr >> 6; // cache line granularity
    uint64_t delta = addr >= last_addr[set] ? addr - last_addr[set] : last_addr[set] - addr;
    if (delta == 1) stream_window[set] += 1;
    else if (stream_window[set] > 0) stream_window[set] -= 1;
    last_addr[set] = addr;
    return stream_window[set] >= STREAM_DELTA_THRESHOLD;
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
    // Standard SRRIP: evict line with RRPV==3, else increment all RRPVs and retry
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; way++) {
            if (rrpv[set][way] == 3)
                return way;
        }
        for (uint32_t way = 0; way < LLC_WAYS; way++)
            if (rrpv[set][way] < 3)
                rrpv[set][way]++;
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
    // Streaming detection for this set
    bool streaming = is_streaming(set, paddr);

    // SHiP signature
    uint16_t signature = (uint16_t)((PC ^ (PC >> 8)) & (SHIP_SIGNATURE_COUNT - 1));
    line_signature[set][way] = signature;

    // Update SHiP table if hit or eviction
    if (hit) {
        if (ship_table[signature].counter < ((1 << SHIP_COUNTER_BITS) - 1))
            ship_table[signature].counter++;
        rrpv[set][way] = 0;
    } else {
        // Dead-block feedback on victim
        uint16_t victim_sig = line_signature[set][way];
        if (ship_table[victim_sig].counter > 0)
            ship_table[victim_sig].counter--;
    }

    // Insertion policy
    uint8_t insert_rrpv = 2; // default SRRIP
    // Streaming bypass: insert at distant RRPV if streaming detected
    if (streaming) {
        insert_rrpv = STREAM_BYPASS_RRPV;
    } else {
        // SHiP-based: if signature is hot, insert at RRPV=0, else at 2
        if (ship_table[signature].counter >= 2)
            insert_rrpv = 0;
        else
            insert_rrpv = 2;

        // DIP-style: leader sets steer PSEL, others follow majority
        if (is_lip_leader(set)) {
            insert_rrpv = 3; // LIP: always insert at distant RRPV
            dip_psel = std::min<uint16_t>(dip_psel + (hit ? 1 : 0), (1 << DIP_PSEL_BITS) - 1);
        } else if (is_bip_leader(set)) {
            insert_rrpv = (rand() % 32 == 0) ? 0 : 3; // BIP: 1/32 at RRPV=0, else distant
            dip_psel = std::max<uint16_t>(dip_psel - (hit ? 1 : 0), 0u);
        } else if (use_lip()) {
            insert_rrpv = 3;
        }
    }
    rrpv[set][way] = insert_rrpv;
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "SHiP-SB-DIP policy stats: (PSEL=" << dip_psel << ")\n";
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Optionally print streaming window stats for debugging
}