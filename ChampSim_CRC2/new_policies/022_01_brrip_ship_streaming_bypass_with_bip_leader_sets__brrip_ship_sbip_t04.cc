#include <vector>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- RRIP metadata: 2-bit RRPV per block ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// --- SHiP-lite: 5-bit PC signature per block, 2-bit outcome counter per signature ---
#define SIG_BITS 5
#define SIG_TABLE_SIZE 32
uint8_t block_sig[LLC_SETS][LLC_WAYS];       // Per-block signature (5 bits)
uint8_t sig_outcome[SIG_TABLE_SIZE];         // 2-bit saturating counter per signature

// --- Streaming detector: per-set, stride, monotonic counter (2 bits) ---
uint64_t last_addr[LLC_SETS];
int64_t last_stride[LLC_SETS];
uint8_t monotonic_count[LLC_SETS];
#define STREAM_THRESHOLD 3 // streaming if monotonic_count >= 3

// --- Set-dueling for BRRIP vs BIP, global PSEL (10 bits) ---
#define DUEL_LEADER_SETS 32
uint8_t is_bip_leader[LLC_SETS]; // 1 if BIP leader, 0 if BRRIP leader, else follower
uint16_t PSEL = 512; // 10-bit, 0=BRRIP, 1023=BIP

// Helper: select leader sets (first 32 for BRRIP, next 32 for BIP)
void init_leader_sets() {
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        is_bip_leader[set] = 0;
    for (uint32_t i = 0; i < DUEL_LEADER_SETS; ++i)
        is_bip_leader[i] = 0; // BRRIP leaders
    for (uint32_t i = 0; i < DUEL_LEADER_SETS; ++i)
        is_bip_leader[DUEL_LEADER_SETS + i] = 1; // BIP leaders
}

// Initialize replacement state
void InitReplacementState() {
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            rrpv[set][way] = 3;
            block_sig[set][way] = 0;
        }
        last_addr[set] = 0;
        last_stride[set] = 0;
        monotonic_count[set] = 0;
        is_bip_leader[set] = 0;
    }
    for (int i = 0; i < SIG_TABLE_SIZE; ++i)
        sig_outcome[i] = 1;
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
    // Standard RRIP victim selection
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (rrpv[set][way] == 3)
                return way;
        }
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

    // --- SHiP signature ---
    uint8_t sig = ((PC >> 2) ^ (set & 0x1F)) & ((1 << SIG_BITS) - 1);

    // --- Set-dueling update ---
    bool is_leader = (set < DUEL_LEADER_SETS * 2);
    if (is_leader) {
        // On hit, reward the policy of the leader set
        if (hit) {
            if (is_bip_leader[set]) {
                if (PSEL < 1023) PSEL++;
            } else {
                if (PSEL > 0) PSEL--;
            }
        }
    }

    // --- Streaming detection ---
    bool stream_detected = (monotonic_count[set] >= STREAM_THRESHOLD);

    // --- SHiP outcome ---
    bool hot_sig = (sig_outcome[sig] >= 2);

    // --- Insertion logic ---
    // Streaming sets: bypass insertion (do not update block metadata)
    if (stream_detected && !hit) {
        // Bypass: do not insert block, leave victim as is
        // (simulate by setting RRPV=3, so block will be evicted quickly)
        rrpv[set][way] = 3;
        block_sig[set][way] = sig; // Still update signature for tracking
        return;
    }

    // On hit: reward signature, set MRU
    if (hit) {
        if (sig_outcome[block_sig[set][way]] < 3)
            sig_outcome[block_sig[set][way]]++;
        rrpv[set][way] = 0;
    } else {
        // On miss/replacement, penalize victim's signature if not reused
        uint8_t victim_sig = block_sig[set][way];
        if (sig_outcome[victim_sig] > 0)
            sig_outcome[victim_sig]--;
        block_sig[set][way] = sig;

        // Choose insertion depth: BRRIP vs BIP, SHiP-hot overrides to MRU
        if (is_leader) {
            if (is_bip_leader[set]) {
                // BIP: Insert at MRU (RRPV=0) with probability 1/32, else LRU (RRPV=3)
                static uint32_t bip_ctr = 0;
                bip_ctr = (bip_ctr + 1) & 0x1F;
                rrpv[set][way] = (bip_ctr == 0) ? 0 : 3;
            } else {
                // BRRIP: Insert at MRU (RRPV=0) with probability 1/32, else LRU (RRPV=3)
                static uint32_t brrip_ctr = 0;
                brrip_ctr = (brrip_ctr + 1) & 0x1F;
                rrpv[set][way] = (brrip_ctr == 0) ? 0 : 3;
            }
        } else {
            // Followers use global PSEL
            if (PSEL >= 512) {
                // BIP: Insert at MRU (RRPV=0) with probability 1/32, else LRU (RRPV=3)
                static uint32_t bip_ctr_f = 0;
                bip_ctr_f = (bip_ctr_f + 1) & 0x1F;
                rrpv[set][way] = (bip_ctr_f == 0) ? 0 : 3;
            } else {
                // BRRIP: Insert at MRU (RRPV=0) with probability 1/32, else LRU (RRPV=3)
                static uint32_t brrip_ctr_f = 0;
                brrip_ctr_f = (brrip_ctr_f + 1) & 0x1F;
                rrpv[set][way] = (brrip_ctr_f == 0) ? 0 : 3;
            }
            // SHiP-hot override: always MRU
            if (hot_sig)
                rrpv[set][way] = 0;
        }
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    int hot_sigs = 0, cold_sigs = 0;
    for (int i = 0; i < SIG_TABLE_SIZE; ++i) {
        if (sig_outcome[i] >= 2) hot_sigs++;
        else cold_sigs++;
    }
    std::cout << "BRRIP-SHiP-SBIP: Hot signatures: " << hot_sigs
              << " / " << SIG_TABLE_SIZE << std::endl;
    std::cout << "BRRIP-SHiP-SBIP: Cold signatures: " << cold_sigs << std::endl;

    int streaming_sets = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        if (monotonic_count[set] >= STREAM_THRESHOLD) streaming_sets++;
    std::cout << "BRRIP-SHiP-SBIP: Streaming sets: " << streaming_sets
              << " / " << LLC_SETS << std::endl;

    std::cout << "BRRIP-SHiP-SBIP: Global PSEL = " << PSEL << " (BRRIP<512<BIP)" << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    int streaming_sets = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        if (monotonic_count[set] >= STREAM_THRESHOLD) streaming_sets++;
    std::cout << "BRRIP-SHiP-SBIP: Streaming sets: " << streaming_sets << std::endl;
    std::cout << "BRRIP-SHiP-SBIP: Global PSEL = " << PSEL << std::endl;
}