#include <vector>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- PC-temporal signature: 6 bits per block, 2-bit outcome per signature ---
#define SIG_BITS 6
#define SIG_TABLE_SIZE 64
uint8_t block_sig[LLC_SETS][LLC_WAYS];       // Per-block signature (6 bits)
uint8_t sig_outcome[SIG_TABLE_SIZE];         // 2-bit saturating counter per signature

// --- SRRIP metadata: 2-bit RRPV per block ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// --- BRRIP/SRRIP set-dueling: 32 leader sets, 10-bit PSEL ---
#define LEADER_SETS 32
#define PSEL_BITS 10
#define PSEL_MAX ((1 << PSEL_BITS) - 1)
uint16_t PSEL = PSEL_MAX / 2;
bool is_srrip_leader[LLC_SETS];
bool is_brrip_leader[LLC_SETS];

// --- Streaming detector: per-set, stride, monotonic counter (2 bits) ---
uint64_t last_addr[LLC_SETS];
int64_t last_stride[LLC_SETS];
uint8_t monotonic_count[LLC_SETS];
#define STREAM_THRESHOLD 2 // streaming if monotonic_count >= 2

// --- Simulated global cycle for temporal signature (low bits only) ---
uint64_t global_cycle = 0;

// Initialize replacement state
void InitReplacementState() {
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            rrpv[set][way] = 2;
            block_sig[set][way] = 0;
        }
        last_addr[set] = 0;
        last_stride[set] = 0;
        monotonic_count[set] = 0;
        // Assign leader sets for SRRIP/BRRIP
        is_srrip_leader[set] = (set < LEADER_SETS);
        is_brrip_leader[set] = (set >= LLC_SETS - LEADER_SETS);
    }
    for (int i = 0; i < SIG_TABLE_SIZE; ++i)
        sig_outcome[i] = 1;
    PSEL = PSEL_MAX / 2;
    global_cycle = 0;
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
    // Standard SRRIP victim selection
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
    global_cycle += 1; // emulate time advancing

    // --- Streaming detector update ---
    int64_t stride = (last_addr[set] == 0) ? 0 : int64_t(paddr) - int64_t(last_addr[set]);
    if (last_addr[set] != 0 && stride == last_stride[set] && stride != 0) {
        if (monotonic_count[set] < 3) monotonic_count[set]++;
    } else {
        if (monotonic_count[set] > 0) monotonic_count[set]--;
    }
    last_addr[set] = paddr;
    last_stride[set] = stride;

    // --- PC-temporal signature ---
    uint8_t sig = ((PC >> 2) ^ (global_cycle & 0x3F)) & ((1 << SIG_BITS) - 1);

    // --- Outcome update ---
    if (hit) {
        rrpv[set][way] = 0; // promote to MRU
        if (sig_outcome[block_sig[set][way]] < 3)
            sig_outcome[block_sig[set][way]]++;
    } else {
        // On eviction, penalize outcome if block was not reused
        uint8_t victim_sig = block_sig[set][way];
        if (sig_outcome[victim_sig] > 0)
            sig_outcome[victim_sig]--;

        // Insert new block with signature
        block_sig[set][way] = sig;

        // --- Streaming bypass logic ---
        bool stream_detected = (monotonic_count[set] >= STREAM_THRESHOLD);
        bool bypass_block = (stream_detected && sig_outcome[sig] < 2);

        if (bypass_block) {
            // Bypass: set RRPV to max so immediately evicted
            rrpv[set][way] = 3;
        } else {
            // --- SRRIP/BRRIP set-dueling for insertion depth ---
            bool use_brrip = false;
            if (is_brrip_leader[set])
                use_brrip = true;
            else if (is_srrip_leader[set])
                use_brrip = false;
            else
                use_brrip = (PSEL < (PSEL_MAX / 2));

            // If signature is "hot", always insert at MRU (0)
            if (sig_outcome[sig] >= 2) {
                rrpv[set][way] = 0;
            } else if (use_brrip) {
                // BRRIP: insert at RRPV=2 with high probability, MRU (0) with low probability
                if ((rand() % 32) < 1)
                    rrpv[set][way] = 0;
                else
                    rrpv[set][way] = 2;
            } else {
                // SRRIP: always insert at RRPV=2
                rrpv[set][way] = 2;
            }
        }

        // --- PSEL update ---
        if (is_brrip_leader[set]) {
            if (hit && !bypass_block && rrpv[set][way] == 0 && !stream_detected)
                if (PSEL < PSEL_MAX) PSEL++;
        }
        if (is_srrip_leader[set]) {
            if (hit && !bypass_block && rrpv[set][way] == 0 && !stream_detected)
                if (PSEL > 0) PSEL--;
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
    std::cout << "SRRIP-X: Hot signatures: " << hot_sigs
              << " / " << SIG_TABLE_SIZE << std::endl;
    std::cout << "SRRIP-X: Cold signatures: " << cold_sigs << std::endl;

    int streaming_sets = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        if (monotonic_count[set] >= STREAM_THRESHOLD) streaming_sets++;
    std::cout << "SRRIP-X: Streaming sets: " << streaming_sets
              << " / " << LLC_SETS << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    int streaming_sets = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        if (monotonic_count[set] >= STREAM_THRESHOLD) streaming_sets++;
    std::cout << "SRRIP-X: Streaming sets: " << streaming_sets << std::endl;
}