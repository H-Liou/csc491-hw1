#include <vector>
#include <cstdint>
#include <iostream>
#include <algorithm>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// Dead-Block Indicator (DBI) parameters
#define DBI_BITS 2
#define DBI_MAX ((1<<DBI_BITS)-1)
#define DBI_DECAY_INTERVAL 1000000 // cycles between global DBI decay

// DIP-style set-dueling
#define NUM_LEADER_SETS 32
#define PSEL_BITS 10
#define PSEL_MAX ((1<<PSEL_BITS)-1)
#define PSEL_INIT (PSEL_MAX/2)

// Per-block replacement state
struct block_state_t {
    uint8_t dbi;   // 2 bits: dead-block indicator
    uint8_t lru;   // 4 bits: LRU position (0 = MRU, 15 = LRU)
    bool valid;
};
std::vector<std::vector<block_state_t>> blocks(LLC_SETS, std::vector<block_state_t>(LLC_WAYS));

// Set-dueling leader sets
std::vector<uint8_t> leader_sets(LLC_SETS, 0); // 0: follower, 1: LIP leader, 2: BIP leader
uint32_t lip_leader_cnt = 0, bip_leader_cnt = 0;
uint32_t PSEL = PSEL_INIT;

// Decay timer
uint64_t dbi_timer = 0;

// --- Init ---
void InitReplacementState() {
    lip_leader_cnt = 0; bip_leader_cnt = 0;
    for (uint32_t s = 0; s < LLC_SETS; s++) {
        for (uint32_t w = 0; w < LLC_WAYS; w++) {
            blocks[s][w] = {0, w, false};
        }
        leader_sets[s] = 0;
    }
    // Leader set assignment using coprime strides
    for (uint32_t i = 0; i < NUM_LEADER_SETS; i++) {
        uint32_t lip_set = (i * 37) % LLC_SETS;
        uint32_t bip_set = (i * 71 + 13) % LLC_SETS;
        if (leader_sets[lip_set] == 0) { leader_sets[lip_set] = 1; lip_leader_cnt++; }
        if (leader_sets[bip_set] == 0) { leader_sets[bip_set] = 2; bip_leader_cnt++; }
    }
    PSEL = PSEL_INIT;
    dbi_timer = 0;
}

// --- Victim selection: prefer dead blocks, else LRU ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Find block with DBI == DBI_MAX (dead), pick oldest LRU among them
    uint32_t victim = 0;
    bool found_dead = false;
    uint8_t oldest_lru = 0;
    for (uint32_t w = 0; w < LLC_WAYS; w++) {
        if (blocks[set][w].valid && blocks[set][w].dbi == DBI_MAX) {
            if (!found_dead || blocks[set][w].lru > oldest_lru) {
                victim = w;
                oldest_lru = blocks[set][w].lru;
                found_dead = true;
            }
        }
    }
    if (found_dead)
        return victim;
    // Otherwise, pick true LRU (highest lru value)
    uint8_t max_lru = 0;
    for (uint32_t w = 0; w < LLC_WAYS; w++) {
        if (blocks[set][w].valid && blocks[set][w].lru >= max_lru) {
            victim = w;
            max_lru = blocks[set][w].lru;
        }
    }
    return victim;
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
    // Update DBI decay timer
    dbi_timer++;
    if (dbi_timer % DBI_DECAY_INTERVAL == 0) {
        // Decay all DBIs (prevent stuck dead classification)
        for (uint32_t s = 0; s < LLC_SETS; s++) {
            for (uint32_t w = 0; w < LLC_WAYS; w++) {
                if (blocks[s][w].dbi > 0)
                    blocks[s][w].dbi--;
            }
        }
    }

    // On hit: reset DBI, update LRU
    if (hit) {
        blocks[set][way].dbi = 0;
        // LRU update: move to MRU
        uint8_t old_lru = blocks[set][way].lru;
        for (uint32_t w = 0; w < LLC_WAYS; w++) {
            if (blocks[set][w].valid && blocks[set][w].lru < old_lru)
                blocks[set][w].lru++;
        }
        blocks[set][way].lru = 0;
        return;
    }

    // On miss: increment DBI for victim
    if (blocks[set][way].valid && blocks[set][way].dbi < DBI_MAX)
        blocks[set][way].dbi++;

    // DIP-style insertion: leader sets, else PSEL
    bool use_lip = false;
    if (leader_sets[set] == 1)
        use_lip = true;
    else if (leader_sets[set] == 2)
        use_lip = false;
    else
        use_lip = (PSEL >= PSEL_MAX/2);

    // LIP: insert at LRU position (lru = LLC_WAYS-1)
    // BIP: insert at MRU (lru = 0) with small probability (1/32), else LRU
    uint8_t ins_lru;
    if (use_lip) {
        ins_lru = LLC_WAYS-1;
    } else {
        static uint32_t bip_rnd = 0;
        bip_rnd = (bip_rnd+1) & 0x1F;
        ins_lru = (bip_rnd == 0) ? 0 : (LLC_WAYS-1);
    }

    blocks[set][way].dbi = 0;
    blocks[set][way].lru = ins_lru;
    blocks[set][way].valid = true;

    // Update LRU positions for others
    for (uint32_t w = 0; w < LLC_WAYS; w++) {
        if (w != way && blocks[set][w].valid) {
            if (blocks[set][w].lru < ins_lru)
                blocks[set][w].lru++;
        }
    }

    // PSEL update (misses in leader sets)
    if (leader_sets[set] == 1) {
        if (!hit && PSEL < PSEL_MAX) PSEL++;
    } else if (leader_sets[set] == 2) {
        if (!hit && PSEL > 0) PSEL--;
    }
}

// --- Print stats ---
void PrintStats() {
    uint64_t dead_blocks = 0, live_blocks = 0;
    for (uint32_t s = 0; s < LLC_SETS; s++) {
        for (uint32_t w = 0; w < LLC_WAYS; w++) {
            if (blocks[s][w].valid) {
                if (blocks[s][w].dbi == DBI_MAX) dead_blocks++;
                else live_blocks++;
            }
        }
    }
    std::cout << "DBI-LIP: Dead blocks=" << dead_blocks << ", Live=" << live_blocks << std::endl;
    std::cout << "DBI-LIP: PSEL=" << PSEL << "/" << PSEL_MAX << std::endl;
    std::cout << "DBI-LIP: Leader sets: LIP=" << lip_leader_cnt << " BIP=" << bip_leader_cnt << std::endl;
}

// --- Print heartbeat stats ---
void PrintStats_Heartbeat() {
    // No periodic stats needed
}