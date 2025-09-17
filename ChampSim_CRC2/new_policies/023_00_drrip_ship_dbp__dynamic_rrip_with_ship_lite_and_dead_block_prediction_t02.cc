#include <vector>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- RRIP metadata: 2-bit RRPV per block ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// --- DRRIP set-dueling: 64 leader sets, 10-bit PSEL ---
#define DUEL_LEADER_SETS 64
uint8_t is_bip_leader[LLC_SETS]; // 1 if BIP leader, 0 if SRRIP leader, else follower
uint16_t PSEL = 512; // 10-bit, 0=SRRIP, 1023=BIP

// --- SHiP-lite: 5-bit PC signature per block, 2-bit outcome counter per signature ---
#define SIG_BITS 5
#define SIG_TABLE_SIZE 32
uint8_t block_sig[LLC_SETS][LLC_WAYS];       // Per-block signature (5 bits)
uint8_t sig_outcome[SIG_TABLE_SIZE];         // 2-bit saturating counter per signature

// --- Dead-block predictor: 2-bit reuse counter per block ---
uint8_t reuse_ctr[LLC_SETS][LLC_WAYS];       // 2 bits per block

// --- Periodic decay for dead-block predictor ---
uint64_t global_access_ctr = 0;
#define DBP_DECAY_PERIOD 8192

// Helper: select leader sets (first 64 for SRRIP, next 64 for BIP)
void init_leader_sets() {
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        is_bip_leader[set] = 0;
    for (uint32_t i = 0; i < DUEL_LEADER_SETS; ++i)
        is_bip_leader[i] = 0; // SRRIP leaders
    for (uint32_t i = 0; i < DUEL_LEADER_SETS; ++i)
        is_bip_leader[DUEL_LEADER_SETS + i] = 1; // BIP leaders
}

// Initialize replacement state
void InitReplacementState() {
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            rrpv[set][way] = 2;
            block_sig[set][way] = 0;
            reuse_ctr[set][way] = 1;
        }
        is_bip_leader[set] = 0;
    }
    for (int i = 0; i < SIG_TABLE_SIZE; ++i)
        sig_outcome[i] = 1;
    PSEL = 512;
    global_access_ctr = 0;
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
    // Prefer blocks predicted dead (reuse_ctr==0) and RRPV==3
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (rrpv[set][way] == 3 && reuse_ctr[set][way] == 0)
                return way;
        }
        // If none predicted dead, fall back to standard RRIP victim
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (rrpv[set][way] == 3)
                return way;
        }
        // Increment RRPV for all ways
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
    global_access_ctr++;

    // --- Periodic decay for dead-block predictor ---
    if ((global_access_ctr & (DBP_DECAY_PERIOD-1)) == 0) {
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            for (uint32_t w = 0; w < LLC_WAYS; ++w)
                if (reuse_ctr[s][w] > 0)
                    reuse_ctr[s][w]--;
    }

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

    // --- SHiP outcome ---
    bool hot_sig = (sig_outcome[sig] >= 2);

    if (hit) {
        // On hit, reward signature and set block to MRU
        if (sig_outcome[block_sig[set][way]] < 3)
            sig_outcome[block_sig[set][way]]++;
        rrpv[set][way] = 0;
        // Dead-block predictor: increment reuse counter (max 3)
        if (reuse_ctr[set][way] < 3)
            reuse_ctr[set][way]++;
    } else {
        // On miss/replacement, penalize victim's signature if not reused
        uint8_t victim_sig = block_sig[set][way];
        if (sig_outcome[victim_sig] > 0)
            sig_outcome[victim_sig]--;
        block_sig[set][way] = sig;

        // Dead-block predictor: reset reuse counter on insertion
        // If predicted dead (reuse_ctr==0), insert at LRU (RRPV=3)
        if (reuse_ctr[set][way] == 0) {
            rrpv[set][way] = 3;
            reuse_ctr[set][way] = 1; // Give a chance for reuse
            return;
        }

        // --- DRRIP insertion logic ---
        if (is_leader) {
            if (is_bip_leader[set]) {
                // BIP: insert at MRU with low probability (1/32), else distant
                static uint32_t bip_ctr = 0;
                bip_ctr = (bip_ctr + 1) & 0x1F;
                rrpv[set][way] = (bip_ctr == 0) ? 0 : 2;
            } else {
                // SRRIP: hot signature gets MRU, else distant
                rrpv[set][way] = hot_sig ? 0 : 2;
            }
        } else {
            // Followers use global PSEL
            if (PSEL >= 512) {
                // BIP: insert at MRU with low probability, else distant
                static uint32_t bip_ctr = 0;
                bip_ctr = (bip_ctr + 1) & 0x1F;
                rrpv[set][way] = (bip_ctr == 0) ? 0 : 2;
            } else {
                // SRRIP: hot signature gets MRU, else distant
                rrpv[set][way] = hot_sig ? 0 : 2;
            }
        }
        // Dead-block predictor: reset reuse counter on insertion
        reuse_ctr[set][way] = 1;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    int hot_sigs = 0, cold_sigs = 0;
    for (int i = 0; i < SIG_TABLE_SIZE; ++i) {
        if (sig_outcome[i] >= 2) hot_sigs++;
        else cold_sigs++;
    }
    std::cout << "DRRIP-SHiP-DBP: Hot signatures: " << hot_sigs
              << " / " << SIG_TABLE_SIZE << std::endl;
    std::cout << "DRRIP-SHiP-DBP: Cold signatures: " << cold_sigs << std::endl;

    int dead_blocks = 0, live_blocks = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (reuse_ctr[set][way] == 0) dead_blocks++;
            else live_blocks++;
    std::cout << "DRRIP-SHiP-DBP: Dead blocks: " << dead_blocks
              << " / " << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "DRRIP-SHiP-DBP: Live blocks: " << live_blocks << std::endl;

    std::cout << "DRRIP-SHiP-DBP: Global PSEL = " << PSEL << " (SRRIP<512<BIP)" << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    int dead_blocks = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (reuse_ctr[set][way] == 0) dead_blocks++;
    std::cout << "DRRIP-SHiP-DBP: Dead blocks: " << dead_blocks << std::endl;
    std::cout << "DRRIP-SHiP-DBP: Global PSEL = " << PSEL << std::endl;
}