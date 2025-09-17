#include <vector>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// DIP parameters
#define NUM_LEADER_SETS 32
#define PSEL_BITS 10
#define PSEL_MAX ((1<<PSEL_BITS)-1)
#define PSEL_INIT (PSEL_MAX/2)
#define BIP_PROB 32 // Insert at MRU every 1/BIP_PROB fills

// Dead-block counter
#define DBC_BITS 2
#define DBC_MAX ((1<<DBC_BITS)-1)
#define DBC_DECAY_PERIOD 8192 // Decay every 8192 fills

struct block_state_t {
    uint8_t rrpv; // 2 bits: RRIP value
    uint8_t dbc;  // 2 bits: dead-block counter
    bool valid;
};
std::vector<std::vector<block_state_t>> blocks(LLC_SETS, std::vector<block_state_t>(LLC_WAYS));

// Set-dueling
std::vector<uint8_t> leader_sets(LLC_SETS, 0); // 0: follower, 1: LIP leader, 2: BIP leader
uint32_t lip_leader_cnt = 0, bip_leader_cnt = 0;
uint32_t PSEL = PSEL_INIT;
uint64_t fill_count = 0;

// --- Init ---
void InitReplacementState() {
    lip_leader_cnt = 0; bip_leader_cnt = 0; PSEL = PSEL_INIT; fill_count = 0;
    for (uint32_t s = 0; s < LLC_SETS; s++) {
        for (uint32_t w = 0; w < LLC_WAYS; w++)
            blocks[s][w] = {3, 0, false}; // RRPV=3 (distant), DBC=0, invalid
        leader_sets[s] = 0;
    }
    for (uint32_t i = 0; i < NUM_LEADER_SETS; i++) {
        uint32_t lip_set = (i * 37) % LLC_SETS;
        uint32_t bip_set = (i * 71 + 13) % LLC_SETS;
        if (leader_sets[lip_set] == 0) { leader_sets[lip_set] = 1; lip_leader_cnt++; }
        if (leader_sets[bip_set] == 0) { leader_sets[bip_set] = 2; bip_leader_cnt++; }
    }
}

// --- Victim selection (dead-block aware RRIP) ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Prefer lines with dbc==0 (likely dead)
    for (uint32_t w = 0; w < LLC_WAYS; w++)
        if (blocks[set][w].valid && blocks[set][w].dbc == 0)
            return w;
    // Standard RRIP victim search
    while(true) {
        for (uint32_t w = 0; w < LLC_WAYS; w++)
            if (blocks[set][w].rrpv == 3)
                return w;
        for (uint32_t w = 0; w < LLC_WAYS; w++)
            if (blocks[set][w].rrpv < 3)
                blocks[set][w].rrpv++;
    }
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
    fill_count++;
    // Dead-block counter decay (periodic)
    if ((fill_count & (DBC_DECAY_PERIOD-1)) == 0) {
        for (uint32_t s = 0; s < LLC_SETS; s++)
            for (uint32_t w = 0; w < LLC_WAYS; w++)
                if (blocks[s][w].dbc > 0) blocks[s][w].dbc--;
    }

    // On hit: set RRPV=0 (MRU), increment DBC
    if (hit) {
        blocks[set][way].rrpv = 0;
        if (blocks[set][way].dbc < DBC_MAX) blocks[set][way].dbc++;
        blocks[set][way].valid = true;
        return;
    }

    // On miss: reset DBC for incoming block
    blocks[set][way].dbc = 0;

    // DIP insertion policy
    uint8_t ins_rrpv = 3; // LIP: insert as LRU
    bool use_bip = false;
    if (leader_sets[set] == 1) { // LIP leader
        ins_rrpv = 3;
    } else if (leader_sets[set] == 2) { // BIP leader
        use_bip = true;
    } else {
        // Followers use PSEL to pick
        if (PSEL >= PSEL_MAX/2)
            ins_rrpv = 3; // LIP
        else
            use_bip = true;
    }
    if (use_bip) {
        // BIP: insert as MRU (RRPV=0) every 1/BIP_PROB fills, else LRU
        ins_rrpv = ((fill_count % BIP_PROB) == 0) ? 0 : 3;
    }
    blocks[set][way].rrpv = ins_rrpv;
    blocks[set][way].valid = true;

    // Update PSEL for misses in leader sets
    if (leader_sets[set] == 1) {
        if (!hit && PSEL < PSEL_MAX) PSEL++;
    } else if (leader_sets[set] == 2) {
        if (!hit && PSEL > 0) PSEL--;
    }
}

// --- Print stats ---
void PrintStats() {
    uint64_t dead_blocks = 0, total_blocks = 0;
    for (uint32_t s = 0; s < LLC_SETS; s++)
        for (uint32_t w = 0; w < LLC_WAYS; w++) {
            if (blocks[s][w].valid) {
                total_blocks++;
                if (blocks[s][w].dbc == 0) dead_blocks++;
            }
        }
    std::cout << "DIP-LIP-DBD: Dead blocks=" << dead_blocks << "/" << total_blocks << std::endl;
    std::cout << "DIP-LIP-DBD: PSEL=" << PSEL << "/" << PSEL_MAX << std::endl;
    std::cout << "DIP-LIP-DBD: Leader sets: LIP=" << lip_leader_cnt << " BIP=" << bip_leader_cnt << std::endl;
}

// --- Print heartbeat stats ---
void PrintStats_Heartbeat() {
    // No periodic stats needed
}