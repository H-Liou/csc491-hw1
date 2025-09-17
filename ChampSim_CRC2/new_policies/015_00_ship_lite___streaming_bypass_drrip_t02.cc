#include <vector>
#include <cstdint>
#include <iostream>
#include <algorithm>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// DRRIP parameters
#define RRPV_BITS 2
#define RRPV_MAX ((1<<RRPV_BITS)-1)
#define SRRIP_INSERT 0
#define BRRIP_INSERT (RRPV_MAX-1)

// SHiP-lite parameters
#define SHIP_SIG_BITS 5
#define SHIP_SIG_ENTRIES (LLC_SETS) // 2048 entries
#define SHIP_CTR_BITS 2
#define SHIP_CTR_MAX ((1<<SHIP_CTR_BITS)-1)
#define SHIP_CTR_INIT 1

// Streaming detector
#define STREAM_WINDOW 4
#define STREAM_DELTA_THRESHOLD 3

// DRRIP set-dueling
#define NUM_LEADER_SETS 32
#define PSEL_BITS 10
#define PSEL_MAX ((1<<PSEL_BITS)-1)
#define PSEL_INIT (PSEL_MAX/2)

// Block state
struct block_state_t {
    uint8_t rrpv;      // 2 bits: RRIP value
    uint8_t ship_sig;  // 5 bits: PC signature
    bool valid;
};
std::vector<std::vector<block_state_t>> blocks(LLC_SETS, std::vector<block_state_t>(LLC_WAYS));

// SHiP signature table: 2048 entries × 2 bits
struct ship_entry_t {
    uint8_t ctr; // 2 bits: outcome counter
};
std::vector<ship_entry_t> ship_table(SHIP_SIG_ENTRIES);

// Streaming detector: 1 bit per set
std::vector<uint8_t> streaming_set(LLC_SETS, 0);
std::vector<uint64_t> last_addr(LLC_SETS, 0);
std::vector<uint32_t> stream_delta_ctr(LLC_SETS, 0);

// DRRIP set-dueling
std::vector<uint8_t> leader_sets(LLC_SETS, 0); // 0: follower, 1: SRRIP leader, 2: BRRIP leader
uint32_t sr_leader_cnt = 0, br_leader_cnt = 0;
uint32_t PSEL = PSEL_INIT;

// Helper: get PC signature
inline uint8_t get_ship_sig(uint64_t PC) {
    return (PC ^ (PC >> 5) ^ (PC >> 13)) & ((1<<SHIP_SIG_BITS)-1);
}

void InitReplacementState() {
    sr_leader_cnt = 0; br_leader_cnt = 0;
    for (uint32_t s = 0; s < LLC_SETS; s++) {
        for (uint32_t w = 0; w < LLC_WAYS; w++) {
            blocks[s][w] = {RRPV_MAX, 0, false};
        }
        leader_sets[s] = 0;
        streaming_set[s] = 0;
        last_addr[s] = 0;
        stream_delta_ctr[s] = 0;
    }
    // Assign leader sets
    for (uint32_t i = 0; i < NUM_LEADER_SETS; i++) {
        uint32_t sr_set = (i * 37) % LLC_SETS;
        uint32_t br_set = (i * 71 + 13) % LLC_SETS;
        if (leader_sets[sr_set] == 0) { leader_sets[sr_set] = 1; sr_leader_cnt++; }
        if (leader_sets[br_set] == 0) { leader_sets[br_set] = 2; br_leader_cnt++; }
    }
    PSEL = PSEL_INIT;
    for (uint32_t i = 0; i < SHIP_SIG_ENTRIES; i++)
        ship_table[i].ctr = SHIP_CTR_INIT;
}

// Find victim in the set (RRIP)
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
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
    // Streaming detector: track address deltas
    uint64_t delta = (last_addr[set] == 0) ? 0 : std::abs((int64_t)paddr - (int64_t)last_addr[set]);
    last_addr[set] = paddr;
    if (delta > 0 && delta < 128) { // small stride
        stream_delta_ctr[set]++;
        if (stream_delta_ctr[set] >= STREAM_DELTA_THRESHOLD)
            streaming_set[set] = 1;
    } else {
        stream_delta_ctr[set] = 0;
        streaming_set[set] = 0;
    }

    // Get PC signature
    uint8_t sig = get_ship_sig(PC);

    // On hit: promote block, update SHiP outcome
    if (hit) {
        blocks[set][way].rrpv = SRRIP_INSERT;
        blocks[set][way].valid = true;
        blocks[set][way].ship_sig = sig;
        // Update SHiP outcome counter
        if (ship_table[sig].ctr < SHIP_CTR_MAX)
            ship_table[sig].ctr++;
        return;
    }

    // On miss/fill: update SHiP outcome for victim
    if (blocks[set][way].valid) {
        uint8_t old_sig = blocks[set][way].ship_sig;
        if (ship_table[old_sig].ctr > 0)
            ship_table[old_sig].ctr--;
    }

    // Streaming bypass: if streaming detected, bypass (set RRPV=RRPV_MAX)
    if (streaming_set[set]) {
        blocks[set][way].rrpv = RRPV_MAX;
        blocks[set][way].valid = true;
        blocks[set][way].ship_sig = sig;
        return;
    }

    // SHiP-guided insertion: if PC signature has poor reuse, insert at distant RRPV
    uint8_t ins_rrpv;
    if (ship_table[sig].ctr == 0) {
        ins_rrpv = RRPV_MAX; // likely dead, insert at distant RRPV
    } else if (ship_table[sig].ctr == 1) {
        // Use DRRIP set-dueling for moderate reuse
        if (leader_sets[set] == 1) { // SRRIP leader
            ins_rrpv = SRRIP_INSERT;
        } else if (leader_sets[set] == 2) { // BRRIP leader
            ins_rrpv = BRRIP_INSERT;
        } else {
            ins_rrpv = (PSEL >= PSEL_MAX/2) ? SRRIP_INSERT : BRRIP_INSERT;
        }
    } else {
        ins_rrpv = SRRIP_INSERT; // strong reuse, insert at MRU
    }
    blocks[set][way].rrpv = ins_rrpv;
    blocks[set][way].valid = true;
    blocks[set][way].ship_sig = sig;

    // PSEL update (on misses in leader sets)
    if (leader_sets[set] == 1) {
        if (!hit && PSEL < PSEL_MAX) PSEL++;
    } else if (leader_sets[set] == 2) {
        if (!hit && PSEL > 0) PSEL--;
    }
}

void PrintStats() {
    uint64_t ship_good = 0, ship_bad = 0;
    for (uint32_t i = 0; i < SHIP_SIG_ENTRIES; i++) {
        if (ship_table[i].ctr >= 2) ship_good++;
        else if (ship_table[i].ctr == 0) ship_bad++;
    }
    std::cout << "SHiP-Lite: Good sigs=" << ship_good << " Bad sigs=" << ship_bad << std::endl;
    std::cout << "DRRIP: PSEL=" << PSEL << "/" << PSEL_MAX << std::endl;
    std::cout << "Leader sets: SRRIP=" << sr_leader_cnt << " BRRIP=" << br_leader_cnt << std::endl;
}

void PrintStats_Heartbeat() {
    // No periodic stats needed
}