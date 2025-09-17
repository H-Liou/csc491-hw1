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

// --- Dead-block predictor: 1-bit per block, decayed every N accesses ---
uint8_t dead_block[LLC_SETS][LLC_WAYS];      // 1 if predicted dead, 0 if alive
uint32_t db_decay_counter = 0;
#define DB_DECAY_PERIOD 4096 // Decay every 4096 fills

// --- Set-dueling for SRRIP vs BRRIP, global PSEL (10 bits) ---
#define DUEL_LEADER_SETS 32
uint8_t is_brrip_leader[LLC_SETS]; // 1 if BRRIP leader, 0 if SRRIP leader, else follower
uint16_t PSEL = 512; // 10-bit, 0=SRRIP, 1023=BRRIP

// Helper: select leader sets (first 32 for SRRIP, next 32 for BRRIP)
void init_leader_sets() {
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        is_brrip_leader[set] = 0;
    for (uint32_t i = 0; i < DUEL_LEADER_SETS; ++i)
        is_brrip_leader[i] = 0; // SRRIP leaders
    for (uint32_t i = 0; i < DUEL_LEADER_SETS; ++i)
        is_brrip_leader[DUEL_LEADER_SETS + i] = 1; // BRRIP leaders
}

// Initialize replacement state
void InitReplacementState() {
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            rrpv[set][way] = 2;
            block_sig[set][way] = 0;
            dead_block[set][way] = 0;
        }
        is_brrip_leader[set] = 0;
    }
    for (int i = 0; i < SIG_TABLE_SIZE; ++i)
        sig_outcome[i] = 1;
    PSEL = 512;
    db_decay_counter = 0;
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
    // --- SHiP signature ---
    uint8_t sig = ((PC >> 2) ^ (set & 0x1F)) & ((1 << SIG_BITS) - 1);

    // --- Set-dueling update ---
    bool is_leader = (set < DUEL_LEADER_SETS * 2);
    if (is_leader) {
        // On hit, reward the policy of the leader set
        if (hit) {
            if (is_brrip_leader[set]) {
                if (PSEL < 1023) PSEL++;
            } else {
                if (PSEL > 0) PSEL--;
            }
        }
    }

    // --- Dead-block predictor update ---
    // On fill (miss), if victim was not reused, mark as dead
    if (!hit) {
        uint8_t victim_sig = block_sig[set][way];
        if (sig_outcome[victim_sig] > 0)
            sig_outcome[victim_sig]--;

        // If block was not reused (dead_block==1), keep dead; else, set dead if not hot
        if (dead_block[set][way] == 0 && sig_outcome[victim_sig] < 2)
            dead_block[set][way] = 1;

        block_sig[set][way] = sig;
    }

    // --- Insertion logic ---
    bool hot_sig = (sig_outcome[sig] >= 2);
    bool dead_pred = (dead_block[set][way] == 1);

    if (!hit) {
        // Dead-block bypass: if predicted dead, insert as LRU (RRPV=3)
        if (dead_pred) {
            rrpv[set][way] = 3;
        } else {
            // Leader sets override insertion depth for set-dueling
            if (is_leader) {
                if (is_brrip_leader[set]) {
                    // BRRIP: insert at distant (RRPV=2/3, with 1/32 probability MRU)
                    if ((rand() & 0x1F) == 0)
                        rrpv[set][way] = 0;
                    else
                        rrpv[set][way] = 2 + (rand() & 0x1);
                } else {
                    // SRRIP: hot signature gets MRU, else distant
                    rrpv[set][way] = hot_sig ? 0 : 2;
                }
            } else {
                // Followers use global PSEL
                if (PSEL >= 512) {
                    // BRRIP: mostly distant, rare MRU
                    if ((rand() & 0x1F) == 0)
                        rrpv[set][way] = 0;
                    else
                        rrpv[set][way] = 2 + (rand() & 0x1);
                } else {
                    // SRRIP: hot signature gets MRU, else distant
                    rrpv[set][way] = hot_sig ? 0 : 2;
                }
            }
        }
    } else {
        // On hit, promote block, reward signature, mark as alive
        rrpv[set][way] = 0;
        if (sig_outcome[block_sig[set][way]] < 3)
            sig_outcome[block_sig[set][way]]++;
        dead_block[set][way] = 0;
    }

    // --- Dead-block decay: periodically reset dead prediction to avoid stuck bits ---
    db_decay_counter++;
    if (db_decay_counter % DB_DECAY_PERIOD == 0) {
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            for (uint32_t w = 0; w < LLC_WAYS; ++w)
                dead_block[s][w] = 0;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    int hot_sigs = 0, cold_sigs = 0;
    for (int i = 0; i < SIG_TABLE_SIZE; ++i) {
        if (sig_outcome[i] >= 2) hot_sigs++;
        else cold_sigs++;
    }
    std::cout << "SHiP-DRRIP-DBSB: Hot signatures: " << hot_sigs
              << " / " << SIG_TABLE_SIZE << std::endl;
    std::cout << "SHiP-DRRIP-DBSB: Cold signatures: " << cold_sigs << std::endl;

    int dead_blocks = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (dead_block[set][way]) dead_blocks++;
    std::cout << "SHiP-DRRIP-DBSB: Dead blocks: " << dead_blocks
              << " / " << (LLC_SETS * LLC_WAYS) << std::endl;

    std::cout << "SHiP-DRRIP-DBSB: Global PSEL = " << PSEL << " (SRRIP<512<BRRIP)" << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    int dead_blocks = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (dead_block[set][way]) dead_blocks++;
    std::cout << "SHiP-DRRIP-DBSB: Dead blocks: " << dead_blocks << std::endl;
    std::cout << "SHiP-DRRIP-DBSB: Global PSEL = " << PSEL << std::endl;
}