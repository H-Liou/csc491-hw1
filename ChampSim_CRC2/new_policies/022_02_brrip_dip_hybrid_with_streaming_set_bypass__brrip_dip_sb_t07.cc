#include <vector>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- RRIP metadata: 2-bit RRPV per block ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// --- DRRIP: Set-dueling for SRRIP vs BRRIP, global PSEL (10 bits) ---
#define DUEL_LEADER_SETS 64
uint8_t is_brrip_leader[LLC_SETS]; // 1 for BRRIP leader, 0 for SRRIP leader, else follower
uint16_t PSEL = 512; // 10-bit, 0=SRRIP, 1023=BRRIP

// --- DIP-style insertion: 32 LIP leader sets, 32 BIP leader sets ---
#define DIP_LIP_LEADERS 32
#define DIP_BIP_LEADERS 32
uint8_t is_lip_leader[LLC_SETS]; // 1 for LIP, 0 for BIP, else follower

// --- Streaming detector: per-set stride monotonicity counter (2 bits) ---
uint64_t last_addr[LLC_SETS];
int64_t last_stride[LLC_SETS];
uint8_t monotonic_count[LLC_SETS];
#define STREAM_THRESHOLD 2 // streaming if monotonic_count >= 2

// Helper: select leader sets (first 32 for SRRIP, next 32 for BRRIP, DIP leaders follow)
void init_leader_sets() {
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        is_brrip_leader[set] = 0;
        is_lip_leader[set] = 0;
    }
    for (uint32_t i = 0; i < DUEL_LEADER_SETS / 2; ++i)
        is_brrip_leader[i] = 0; // SRRIP leaders
    for (uint32_t i = 0; i < DUEL_LEADER_SETS / 2; ++i)
        is_brrip_leader[(DUEL_LEADER_SETS / 2) + i] = 1; // BRRIP leaders
    for (uint32_t i = 0; i < DIP_LIP_LEADERS; ++i)
        is_lip_leader[DUEL_LEADER_SETS + i] = 1; // LIP leader sets
    // DIP BIP leaders are sets [DUEL_LEADER_SETS + DIP_LIP_LEADERS, DUEL_LEADER_SETS + DIP_LIP_LEADERS + DIP_BIP_LEADERS)
    // Not explicitly tracked, just for clarity.
}

// Initialize replacement state
void InitReplacementState() {
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            rrpv[set][way] = 2;
        }
        last_addr[set] = 0;
        last_stride[set] = 0;
        monotonic_count[set] = 0;
        is_brrip_leader[set] = 0;
        is_lip_leader[set] = 0;
    }
    PSEL = 512;
    init_leader_sets();
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
    // Streaming sets: always select a block to evict since bypass happens on fill
    // Standard RRIP victim selection
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] < 3)
                ++rrpv[set][way];
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
    int64_t stride = (last_addr[set] == 0) ? 0 : int64_t(paddr) - int64_t(last_addr[set]);
    if (last_addr[set] != 0 && stride == last_stride[set] && stride != 0) {
        if (monotonic_count[set] < 3) monotonic_count[set]++;
    } else {
        if (monotonic_count[set] > 0) monotonic_count[set]--;
    }
    last_addr[set] = paddr;
    last_stride[set] = stride;

    bool stream_detected = (monotonic_count[set] >= STREAM_THRESHOLD);

    // --- DIP-style insertion (leader sets) ---
    bool is_lip = is_lip_leader[set];
    bool is_bip = (!is_lip_leader[set]) && (set >= DUEL_LEADER_SETS && set < DUEL_LEADER_SETS + DIP_LIP_LEADERS + DIP_BIP_LEADERS);

    // --- DRRIP set-dueling update ---
    bool is_duel_leader = (set < DUEL_LEADER_SETS);
    if (is_duel_leader && hit) {
        if (is_brrip_leader[set]) {
            if (PSEL < 1023) PSEL++;
        } else {
            if (PSEL > 0) PSEL--;
        }
    }

    // --- On fill (miss), choose insertion depth ---
    if (!hit) {
        // Streaming sets: full bypass, do not insert (simulate by setting RRPV=3 for all blocks, so victim is immediately available)
        if (stream_detected) {
            rrpv[set][way] = 3;
            return;
        }

        // DIP-style leader sets insertion depth
        if (is_lip) {
            // LIP: always insert at LRU (RRPV=3)
            rrpv[set][way] = 3;
        } else if (is_bip) {
            // BIP: insert at MRU (RRPV=0) with low probability (e.g., 1/32), otherwise LRU
            static uint32_t bip_ptr = 0;
            bip_ptr = (bip_ptr + 1) % 32;
            rrpv[set][way] = (bip_ptr == 0) ? 0 : 3;
        } else {
            // DRRIP followers: global PSEL chooses SRRIP (insert at 2) or BRRIP (insert at 3 with high probability)
            if (PSEL >= 512) {
                // BRRIP: insert at RRPV=3 with 7/8 probability, else RRPV=2
                static uint32_t brrip_ptr = 0;
                brrip_ptr = (brrip_ptr + 1) % 8;
                rrpv[set][way] = (brrip_ptr != 0) ? 3 : 2;
            } else {
                // SRRIP: insert at RRPV=2
                rrpv[set][way] = 2;
            }
        }
    } else {
        // On hit, promote block to MRU (RRPV=0)
        rrpv[set][way] = 0;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    int streaming_sets = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        if (monotonic_count[set] >= STREAM_THRESHOLD) streaming_sets++;
    std::cout << "BRRIP-DIP-SB: Streaming sets: " << streaming_sets << " / " << LLC_SETS << std::endl;
    std::cout << "BRRIP-DIP-SB: Global PSEL = " << PSEL << " (SRRIP<512<BRRIP)" << std::endl;
    int lip_leader = 0, bip_leader = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        lip_leader += is_lip_leader[set];
        bip_leader += (!is_lip_leader[set] && set >= DUEL_LEADER_SETS && set < DUEL_LEADER_SETS + DIP_LIP_LEADERS + DIP_BIP_LEADERS);
    }
    std::cout << "BRRIP-DIP-SB: LIP leader sets: " << lip_leader << ", BIP leader sets: " << bip_leader << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    int streaming_sets = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        if (monotonic_count[set] >= STREAM_THRESHOLD) streaming_sets++;
    std::cout << "BRRIP-DIP-SB: Streaming sets: " << streaming_sets << std::endl;
    std::cout << "BRRIP-DIP-SB: Global PSEL = " << PSEL << std::endl;
}