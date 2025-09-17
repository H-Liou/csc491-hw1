#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- Per-block metadata ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];        // 2 bits per block

// --- SHiP-lite metadata ---
#define SHIP_SIG_BITS 6
#define SHIP_TABLE_SIZE 512
struct SHIPEntry {
    uint8_t reuse_ctr; // 2 bits
    uint8_t valid;
    uint8_t sig;
};
SHIPEntry ship_table[SHIP_TABLE_SIZE];   // 512 entries

// --- Streaming detector metadata ---
uint64_t last_addr[LLC_SETS];            // Last address accessed in set
int64_t last_delta[LLC_SETS];            // Last delta in set
uint8_t stream_score[LLC_SETS];          // 1 byte per set

// --- Leader sets for SHiP learning ---
#define NUM_LEADER_SETS 64
uint8_t leader_set_type[LLC_SETS];       // 0: SHiP leader, 1: normal

// Helper: assign leader sets (first 64 SHiP leader)
void AssignLeaderSets() {
    for (uint32_t i = 0; i < LLC_SETS; ++i) {
        if (i < NUM_LEADER_SETS)
            leader_set_type[i] = 0; // SHiP leader
        else
            leader_set_type[i] = 1; // normal
    }
}

// SHiP signature: 6 bits from PC
inline uint8_t GetSignature(uint64_t PC) {
    return (PC ^ (PC >> 6) ^ (PC >> 12)) & ((1 << SHIP_SIG_BITS) - 1);
}

// SHiP table index
inline uint32_t SHIPIndex(uint8_t sig) {
    return sig;
}

// Initialize replacement state
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv)); // distant
    memset(ship_table, 0, sizeof(ship_table));
    memset(last_addr, 0, sizeof(last_addr));
    memset(last_delta, 0, sizeof(last_delta));
    memset(stream_score, 0, sizeof(stream_score));
    AssignLeaderSets();
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
    // Prefer invalid block
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (!current_set[way].valid)
            return way;

    // Classic RRIP victim selection
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
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
    // --- Streaming detector update ---
    int64_t delta = (int64_t)paddr - (int64_t)last_addr[set];
    if (last_addr[set] != 0) {
        if (delta == last_delta[set] && delta != 0) {
            // Monotonic stride detected
            if (stream_score[set] < 255) stream_score[set]++;
        } else {
            if (stream_score[set] > 0) stream_score[set]--;
        }
    }
    last_delta[set] = delta;
    last_addr[set] = paddr;

    // --- SHiP signature ---
    uint8_t sig = GetSignature(PC);
    uint32_t ship_idx = SHIPIndex(sig);

    // --- SHiP outcome update ---
    if (hit) {
        // On hit, increment reuse counter (max 3)
        if (ship_table[ship_idx].valid && ship_table[ship_idx].reuse_ctr < 3)
            ship_table[ship_idx].reuse_ctr++;
        rrpv[set][way] = 0; // protect block
    } else {
        // On miss, decrement reuse counter (min 0)
        if (ship_table[ship_idx].valid && ship_table[ship_idx].reuse_ctr > 0)
            ship_table[ship_idx].reuse_ctr--;
    }
    ship_table[ship_idx].valid = 1;
    ship_table[ship_idx].sig = sig;

    // --- Streaming bypass logic ---
    bool streaming = (stream_score[set] > 32);

    // --- SHiP-based insertion ---
    uint8_t ins_rrpv = 2; // default: mid
    if (streaming) {
        // Streaming detected: bypass (do not insert) or insert at distant
        ins_rrpv = 3;
    } else {
        // Use SHiP reuse counter to bias insertion
        if (ship_table[ship_idx].reuse_ctr >= 2)
            ins_rrpv = 0; // high reuse: protect
        else if (ship_table[ship_idx].reuse_ctr == 1)
            ins_rrpv = 1; // moderate reuse
        else
            ins_rrpv = 3; // low reuse: distant
    }

    // On fill (miss), set insertion RRPV
    if (!hit)
        rrpv[set][way] = ins_rrpv;

    // --- Periodic streaming score decay (every 4096 fills) ---
    static uint64_t fill_count = 0;
    fill_count++;
    if ((fill_count & 0xFFF) == 0) {
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            if (stream_score[s] > 0)
                stream_score[s]--;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    int protected_blocks = 0, distant_blocks = 0, streaming_sets = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (rrpv[set][way] == 0) protected_blocks++;
            if (rrpv[set][way] == 3) distant_blocks++;
        }
        if (stream_score[set] > 32) streaming_sets++;
    }
    std::cout << "SHiP-Lite + Streaming Bypass Hybrid Policy" << std::endl;
    std::cout << "Protected blocks: " << protected_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "Distant blocks: " << distant_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "Streaming sets: " << streaming_sets << "/" << LLC_SETS << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    int protected_blocks = 0, distant_blocks = 0, streaming_sets = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (rrpv[set][way] == 0) protected_blocks++;
            if (rrpv[set][way] == 3) distant_blocks++;
        }
        if (stream_score[set] > 32) streaming_sets++;
    }
    std::cout << "Protected blocks (heartbeat): " << protected_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "Distant blocks (heartbeat): " << distant_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "Streaming sets (heartbeat): " << streaming_sets << "/" << LLC_SETS << std::endl;
}