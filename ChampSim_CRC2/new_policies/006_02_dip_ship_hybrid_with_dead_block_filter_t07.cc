#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- DIP: Set-dueling for LIP vs BIP ---
#define NUM_LEADER_SETS 32
uint16_t PSEL = 512; // 10-bit counter
bool is_leader_lip[LLC_SETS];
bool is_leader_bip[LLC_SETS];

// --- SHiP-lite: 6-bit PC signature per block, 2-bit outcome counter per signature ---
#define SHIP_SIG_BITS 6
#define SHIP_SIG_ENTRIES (1 << SHIP_SIG_BITS) // 64 entries
uint8_t ship_outcome[SHIP_SIG_ENTRIES]; // 2-bit saturating counter per signature
uint8_t block_sig[LLC_SETS][LLC_WAYS];  // 6-bit signature per block

// --- Dead-block filter: 1-bit dead/live per block, periodic decay ---
uint8_t dead_tag[LLC_SETS][LLC_WAYS]; // 0=live, 1=dead
uint64_t lru_epoch = 0; // For periodic decay

// --- Initialization ---
void InitReplacementState() {
    memset(ship_outcome, 0, sizeof(ship_outcome));
    memset(block_sig, 0, sizeof(block_sig));
    memset(dead_tag, 0, sizeof(dead_tag));
    for (uint32_t s = 0; s < LLC_SETS; ++s) {
        if (s < NUM_LEADER_SETS)
            is_leader_lip[s] = true, is_leader_bip[s] = false;
        else if (s >= LLC_SETS - NUM_LEADER_SETS)
            is_leader_lip[s] = false, is_leader_bip[s] = true;
        else
            is_leader_lip[s] = false, is_leader_bip[s] = false;
    }
    PSEL = 512;
    lru_epoch = 0;
}

// --- Find victim: prioritize dead lines, else LRU ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // First, look for any dead-tagged block
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (dead_tag[set][way])
            return way;
    // Otherwise, fall back to LRU (oldest block)
    uint32_t lru_way = 0;
    uint64_t min_ts = current_set[0].last_touch;
    for (uint32_t way = 1; way < LLC_WAYS; ++way) {
        if (current_set[way].last_touch < min_ts) {
            lru_way = way;
            min_ts = current_set[way].last_touch;
        }
    }
    return lru_way;
}

// --- Update replacement state ---
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
    // --- SHiP signature extraction ---
    uint8_t sig = (PC ^ (paddr >> 6)) & (SHIP_SIG_ENTRIES - 1);

    // --- DIP policy selection ---
    bool use_lip = false;
    if (is_leader_lip[set])
        use_lip = true;
    else if (is_leader_bip[set])
        use_lip = false;
    else
        use_lip = (PSEL >= 512);

    // --- On hit: update SHiP outcome, dead-tag ---
    if (hit) {
        block_sig[set][way] = sig;
        dead_tag[set][way] = 0; // Mark block as live
        // Update SHiP outcome counter (max 3)
        if (ship_outcome[sig] < 3) ship_outcome[sig]++;
        // DIP set-dueling update
        if (is_leader_lip[set]) {
            if (PSEL < 1023) PSEL++;
        } else if (is_leader_bip[set]) {
            if (PSEL > 0) PSEL--;
        }
        return;
    }

    // --- On fill: choose insertion depth ---
    uint8_t ins_pos = 0;
    if (use_lip)
        ins_pos = LLC_WAYS - 1; // LIP: insert at most distant (LRU)
    else
        ins_pos = (rand() % 32 == 0) ? LLC_WAYS - 1 : LLC_WAYS - 2; // BIP: 1/32 at LRU, else next-to-LRU

    // SHiP bias: if outcome counter for sig is high, insert at MRU (0); if low, at LRU (LLC_WAYS-1)
    if (ship_outcome[sig] >= 2)
        ins_pos = 0;
    else if (ship_outcome[sig] == 0)
        ins_pos = LLC_WAYS - 1;

    // Mark block as live on fill
    dead_tag[set][way] = 0;
    block_sig[set][way] = sig;

    // --- On eviction: update SHiP outcome for victim block, dead-tagging ---
    uint8_t victim_sig = block_sig[set][way];
    // If block was not reused (dead-tag set), decrement outcome counter
    if (dead_tag[set][way] && ship_outcome[victim_sig] > 0)
        ship_outcome[victim_sig]--;

    // Periodic decay of dead-tag every 10,000 fills (approx, cheap)
    lru_epoch++;
    if ((lru_epoch & 0x27FF) == 0) {
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            for (uint32_t w = 0; w < LLC_WAYS; ++w)
                dead_tag[s][w] = 0;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "DIP-SHiP Hybrid + Dead-Block Filter: Final statistics." << std::endl;
    std::cout << "PSEL: " << PSEL << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Optionally print SHiP outcome histogram, PSEL
}