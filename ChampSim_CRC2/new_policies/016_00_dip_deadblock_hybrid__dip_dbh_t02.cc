#include <vector>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// RRIP parameters
#define RRPV_BITS 2
#define RRPV_MAX ((1<<RRPV_BITS)-1)
#define LIP_INSERT 0
#define BIP_INSERT (RRPV_MAX)
#define BIP_PROB 32 // Insert at MRU 1/32 times

// Dead-block counter
#define DEAD_BITS 2
#define DEAD_MAX ((1<<DEAD_BITS)-1)
#define DEAD_THRESHOLD 2
#define DEAD_DECAY_INTERVAL 4096

// DIP set-dueling
#define NUM_LEADER_SETS 32
#define PSEL_BITS 10
#define PSEL_MAX ((1<<PSEL_BITS)-1)
#define PSEL_INIT (PSEL_MAX/2)

struct block_state_t {
    uint8_t rrpv;      // 2 bits: RRIP value
    uint8_t dead_cnt;  // 2 bits: dead-block counter
    bool valid;
};
std::vector<std::vector<block_state_t>> blocks(LLC_SETS, std::vector<block_state_t>(LLC_WAYS));

// DIP leader sets
std::vector<uint8_t> leader_sets(LLC_SETS, 0); // 0: follower, 1: LIP leader, 2: BIP leader
uint32_t lip_leader_cnt = 0, bip_leader_cnt = 0;
uint32_t PSEL = PSEL_INIT;

// Dead-block decay
uint64_t access_counter = 0;

// --- Init ---
void InitReplacementState() {
    lip_leader_cnt = 0; bip_leader_cnt = 0;
    for (uint32_t s = 0; s < LLC_SETS; s++) {
        for (uint32_t w = 0; w < LLC_WAYS; w++) {
            blocks[s][w] = {RRPV_MAX, 0, false};
        }
        leader_sets[s] = 0;
    }
    // Randomly select leader sets
    for (uint32_t i = 0; i < NUM_LEADER_SETS; i++) {
        uint32_t lip_set = (i * 37) % LLC_SETS;
        uint32_t bip_set = (i * 71 + 13) % LLC_SETS;
        if (leader_sets[lip_set] == 0) { leader_sets[lip_set] = 1; lip_leader_cnt++; }
        if (leader_sets[bip_set] == 0) { leader_sets[bip_set] = 2; bip_leader_cnt++; }
    }
    PSEL = PSEL_INIT;
    access_counter = 0;
}

// --- Victim selection (RRIP) ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Standard RRIP victim selection
    while(true) {
        for (uint32_t w = 0; w < LLC_WAYS; w++) {
            if (blocks[set][w].rrpv == RRPV_MAX)
                return w;
        }
        for (uint32_t w = 0; w < LLC_WAYS; w++) {
            if (blocks[set][w].rrpv < RRPV_MAX)
                blocks[set][w].rrpv++;
        }
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
    access_counter++;

    // On hit: set block to MRU, reset dead-block counter
    if (hit) {
        blocks[set][way].rrpv = LIP_INSERT;
        blocks[set][way].dead_cnt = 0;
        blocks[set][way].valid = true;
        return;
    }

    // On miss: increment dead-block counter for victim
    if (blocks[set][way].valid) {
        if (blocks[set][way].dead_cnt < DEAD_MAX)
            blocks[set][way].dead_cnt++;
    }

    // Dead-block: if victim's dead_cnt exceeds threshold, insert at distant RRPV
    uint8_t ins_rrpv;
    if (blocks[set][way].dead_cnt >= DEAD_THRESHOLD) {
        ins_rrpv = RRPV_MAX;
    } else {
        // DIP: leader sets decide, others follow PSEL
        if (leader_sets[set] == 1) { // LIP leader
            ins_rrpv = LIP_INSERT;
        } else if (leader_sets[set] == 2) { // BIP leader
            // Insert at MRU 1/BIP_PROB times, else at LRU
            ins_rrpv = ((access_counter & (BIP_PROB-1)) == 0) ? LIP_INSERT : BIP_INSERT;
        } else {
            ins_rrpv = (PSEL >= PSEL_MAX/2) ?
                LIP_INSERT :
                (((access_counter & (BIP_PROB-1)) == 0) ? LIP_INSERT : BIP_INSERT);
        }
    }
    blocks[set][way].rrpv = ins_rrpv;
    blocks[set][way].dead_cnt = 0;
    blocks[set][way].valid = true;

    // PSEL update (misses in leader sets)
    if (leader_sets[set] == 1) {
        if (!hit && PSEL < PSEL_MAX) PSEL++;
    } else if (leader_sets[set] == 2) {
        if (!hit && PSEL > 0) PSEL--;
    }

    // Periodic dead-block decay
    if ((access_counter % DEAD_DECAY_INTERVAL) == 0) {
        for (uint32_t s = 0; s < LLC_SETS; s++) {
            for (uint32_t w = 0; w < LLC_WAYS; w++) {
                if (blocks[s][w].dead_cnt > 0)
                    blocks[s][w].dead_cnt--;
            }
        }
    }
}

// --- Print stats ---
void PrintStats() {
    uint64_t dead_lines = 0;
    for (uint32_t s = 0; s < LLC_SETS; s++)
        for (uint32_t w = 0; w < LLC_WAYS; w++)
            if (blocks[s][w].dead_cnt >= DEAD_THRESHOLD)
                dead_lines++;
    std::cout << "DIP-DBH: Dead lines=" << dead_lines << "/" << (LLC_SETS*LLC_WAYS) << std::endl;
    std::cout << "DIP-DBH: PSEL=" << PSEL << "/" << PSEL_MAX << std::endl;
    std::cout << "DIP-DBH: Leader sets: LIP=" << lip_leader_cnt << " BIP=" << bip_leader_cnt << std::endl;
}

// --- Print heartbeat stats ---
void PrintStats_Heartbeat() {
    // No periodic stats needed
}