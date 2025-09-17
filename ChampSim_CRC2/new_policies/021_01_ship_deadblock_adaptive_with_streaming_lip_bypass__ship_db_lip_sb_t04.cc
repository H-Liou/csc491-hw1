#include <vector>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- SHiP-lite: 5-bit PC signature per block, 2-bit outcome counter per signature ---
#define SIG_BITS 5
#define SIG_TABLE_SIZE 32
uint8_t block_sig[LLC_SETS][LLC_WAYS];       // Per-block signature (5 bits)
uint8_t sig_outcome[SIG_TABLE_SIZE];         // 2-bit saturating counter per signature

// --- RRIP metadata: 2-bit RRPV per block ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// --- Dead-block counter: 2-bit per block (0=hot, 3=dead) ---
uint8_t dead_ctr[LLC_SETS][LLC_WAYS];

// --- Streaming detector: per-set, stride, monotonic counter (2 bits) ---
uint64_t last_addr[LLC_SETS];
int64_t last_stride[LLC_SETS];
uint8_t monotonic_count[LLC_SETS];
#define STREAM_THRESHOLD 2 // streaming if monotonic_count >= 2

// --- Set-dueling for SRRIP vs LIP, global PSEL (10 bits) ---
#define DUEL_LEADER_SETS 32
uint8_t is_lip_leader[LLC_SETS]; // 1 if LIP leader, 0 if SRRIP leader, else follower
uint16_t PSEL = 512; // 10-bit, 0=SRRIP, 1023=LIP

// Helper: select leader sets (first 32 for SRRIP, next 32 for LIP)
void init_leader_sets() {
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        is_lip_leader[set] = 0;
    for (uint32_t i = 0; i < DUEL_LEADER_SETS; ++i)
        is_lip_leader[i] = 0; // SRRIP leaders
    for (uint32_t i = 0; i < DUEL_LEADER_SETS; ++i)
        is_lip_leader[DUEL_LEADER_SETS + i] = 1; // LIP leaders
}

// Initialize replacement state
void InitReplacementState() {
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            rrpv[set][way] = 2;
            block_sig[set][way] = 0;
            dead_ctr[set][way] = 0;
        }
        last_addr[set] = 0;
        last_stride[set] = 0;
        monotonic_count[set] = 0;
        is_lip_leader[set] = 0;
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
    // Prefer dead blocks (dead_ctr==3) for victim selection
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (rrpv[set][way] == 3 || dead_ctr[set][way] == 3)
            return way;
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
            if (is_lip_leader[set]) {
                if (PSEL < 1023) PSEL++;
            } else {
                if (PSEL > 0) PSEL--;
            }
        }
    }

    // --- Dead-block counter update ---
    if (hit) {
        // On hit, block is hot: reset dead_ctr and reward signature
        dead_ctr[set][way] = 0;
        if (sig_outcome[block_sig[set][way]] < 3)
            sig_outcome[block_sig[set][way]]++;
        rrpv[set][way] = 0;
    } else {
        // On miss/replacement, penalize victim's signature if not reused
        uint8_t victim_sig = block_sig[set][way];
        if (sig_outcome[victim_sig] > 0)
            sig_outcome[victim_sig]--;
        block_sig[set][way] = sig;

        // Dead-block: increment counter for replaced block
        if (dead_ctr[set][way] < 3)
            dead_ctr[set][way]++;

        // Streaming detection
        bool stream_detected = (monotonic_count[set] >= STREAM_THRESHOLD);
        bool hot_sig = (sig_outcome[sig] >= 2);
        bool dead_block = (dead_ctr[set][way] == 3);

        // Insertion logic: LIP for streaming/dead, SRRIP for others
        if (is_leader) {
            if (is_lip_leader[set]) {
                // LIP: always insert at LRU (RRPV=3)
                rrpv[set][way] = 3;
            } else {
                // SRRIP: hot signature gets MRU, else distant
                rrpv[set][way] = hot_sig ? 0 : 2;
            }
        } else {
            // Followers use global PSEL
            if (PSEL >= 512) {
                // LIP: streaming or dead block gets LRU
                if (stream_detected || dead_block)
                    rrpv[set][way] = 3;
                else
                    rrpv[set][way] = hot_sig ? 0 : 2;
            } else {
                // SRRIP: hot signature gets MRU, else distant
                rrpv[set][way] = hot_sig ? 0 : 2;
            }
        }
    }
    // Periodic dead block decay (every 4096 fills)
    static uint64_t fill_count = 0;
    fill_count++;
    if ((fill_count & 0xFFF) == 0) {
        for (uint32_t w = 0; w < LLC_WAYS; ++w)
            if (dead_ctr[set][w] > 0)
                dead_ctr[set][w]--;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    int hot_sigs = 0, cold_sigs = 0;
    for (int i = 0; i < SIG_TABLE_SIZE; ++i) {
        if (sig_outcome[i] >= 2) hot_sigs++;
        else cold_sigs++;
    }
    std::cout << "SHiP-DB-LIP-SB: Hot signatures: " << hot_sigs
              << " / " << SIG_TABLE_SIZE << std::endl;
    std::cout << "SHiP-DB-LIP-SB: Cold signatures: " << cold_sigs << std::endl;

    int streaming_sets = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        if (monotonic_count[set] >= STREAM_THRESHOLD) streaming_sets++;
    std::cout << "SHiP-DB-LIP-SB: Streaming sets: " << streaming_sets
              << " / " << LLC_SETS << std::endl;

    int dead_blocks = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (dead_ctr[set][way] == 3) dead_blocks++;
    std::cout << "SHiP-DB-LIP-SB: Dead blocks: " << dead_blocks
              << " / " << (LLC_SETS * LLC_WAYS) << std::endl;

    std::cout << "SHiP-DB-LIP-SB: Global PSEL = " << PSEL << " (SRRIP<512<LIP)" << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    int streaming_sets = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        if (monotonic_count[set] >= STREAM_THRESHOLD) streaming_sets++;
    std::cout << "SHiP-DB-LIP-SB: Streaming sets: " << streaming_sets << std::endl;
    int dead_blocks = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (dead_ctr[set][way] == 3) dead_blocks++;
    std::cout << "SHiP-DB-LIP-SB: Dead blocks: " << dead_blocks << std::endl;
    std::cout << "SHiP-DB-LIP-SB: Global PSEL = " << PSEL << std::endl;
}