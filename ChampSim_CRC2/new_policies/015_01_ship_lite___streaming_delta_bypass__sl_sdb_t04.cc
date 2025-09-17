#include <vector>
#include <cstdint>
#include <iostream>
#include <algorithm>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// RRIP parameters
#define RRPV_BITS 2
#define RRPV_MAX ((1<<RRPV_BITS)-1)
#define SRRIP_INSERT 0
#define BRRIP_INSERT (RRPV_MAX-1)

// SHiP-lite parameters
#define SHIP_SIG_BITS 6
#define SHIP_TABLE_SIZE (1<<SHIP_SIG_BITS) // 64
#define SHIP_ENTRIES (LLC_SETS)            // 2048
#define SHIP_COUNTER_BITS 2
#define SHIP_MAX ((1<<SHIP_COUNTER_BITS)-1)
#define SHIP_THRESHOLD 1

// Streaming delta detector
#define DELTA_HISTORY_LEN 4
#define DELTA_STREAM_THRESHOLD 3

// Set-dueling for SHiP vs RRIP
#define NUM_LEADER_SETS 32
#define PSEL_BITS 10
#define PSEL_MAX ((1<<PSEL_BITS)-1)
#define PSEL_INIT (PSEL_MAX/2)

// Block state
struct block_state_t {
    uint8_t rrpv;      // 2 bits: RRIP value
    uint8_t ship_sig;  // 6 bits: PC signature
    bool valid;
};
std::vector<std::vector<block_state_t>> blocks(LLC_SETS, std::vector<block_state_t>(LLC_WAYS));

// SHiP-lite table: per-signature outcome counter
struct ship_entry_t {
    uint8_t counter; // 2 bits
};
std::vector<ship_entry_t> ship_table(SHIP_TABLE_SIZE * SHIP_ENTRIES);

// Streaming detector: per-set delta history (8b/set)
struct delta_detector_t {
    uint64_t last_addr;
    int64_t deltas[DELTA_HISTORY_LEN];
    uint8_t ptr;
    bool streaming;
};
std::vector<delta_detector_t> delta_detector(LLC_SETS);

// Set-dueling leader sets
std::vector<uint8_t> leader_sets(LLC_SETS, 0); // 0: follower, 1: SHiP leader, 2: RRIP leader
uint32_t ship_leader_cnt = 0, rrip_leader_cnt = 0;
uint32_t PSEL = PSEL_INIT;

// --- Helper: get PC signature ---
inline uint8_t get_ship_sig(uint64_t PC, uint32_t set) {
    // Combine PC and set for more diversity
    return ((PC >> 2) ^ set) & (SHIP_TABLE_SIZE-1);
}

// --- Helper: get SHiP table index ---
inline uint32_t get_ship_idx(uint32_t set, uint8_t sig) {
    return (set * SHIP_TABLE_SIZE) + sig;
}

// --- Streaming detector update ---
void update_delta_detector(uint32_t set, uint64_t paddr) {
    auto &det = delta_detector[set];
    int64_t delta = (int64_t)paddr - (int64_t)det.last_addr;
    det.last_addr = paddr;
    det.deltas[det.ptr] = delta;
    det.ptr = (det.ptr + 1) % DELTA_HISTORY_LEN;
    // Check for monotonic pattern
    bool monotonic = true;
    int64_t first = det.deltas[0];
    if (first == 0) monotonic = false;
    for (int i = 1; i < DELTA_HISTORY_LEN; i++) {
        if (det.deltas[i] != first || det.deltas[i] == 0) {
            monotonic = false;
            break;
        }
    }
    det.streaming = monotonic;
}

// --- Init ---
void InitReplacementState() {
    ship_leader_cnt = 0; rrip_leader_cnt = 0;
    for (uint32_t s = 0; s < LLC_SETS; s++) {
        for (uint32_t w = 0; w < LLC_WAYS; w++) {
            blocks[s][w] = {RRPV_MAX, 0, false};
        }
        leader_sets[s] = 0;
        delta_detector[s] = {0, {0,0,0,0}, 0, false};
    }
    for (uint32_t i = 0; i < NUM_LEADER_SETS; i++) {
        uint32_t ship_set = (i * 37) % LLC_SETS;
        uint32_t rrip_set = (i * 71 + 13) % LLC_SETS;
        if (leader_sets[ship_set] == 0) { leader_sets[ship_set] = 1; ship_leader_cnt++; }
        if (leader_sets[rrip_set] == 0) { leader_sets[rrip_set] = 2; rrip_leader_cnt++; }
    }
    for (auto &entry : ship_table) entry.counter = SHIP_THRESHOLD;
    PSEL = PSEL_INIT;
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
    // Update streaming detector
    update_delta_detector(set, paddr);

    // Get PC signature
    uint8_t sig = get_ship_sig(PC, set);
    uint32_t ship_idx = get_ship_idx(set, sig);

    // On hit: set block to MRU, increment SHiP counter
    if (hit) {
        blocks[set][way].rrpv = SRRIP_INSERT;
        blocks[set][way].ship_sig = sig;
        blocks[set][way].valid = true;
        if (ship_table[ship_idx].counter < SHIP_MAX)
            ship_table[ship_idx].counter++;
        return;
    }

    // On miss: update SHiP counter for victim block
    if (blocks[set][way].valid) {
        uint8_t victim_sig = blocks[set][way].ship_sig;
        uint32_t victim_idx = get_ship_idx(set, victim_sig);
        if (ship_table[victim_idx].counter > 0)
            ship_table[victim_idx].counter--;
    }

    // Streaming bypass: if streaming detected, insert at RRPV_MAX
    if (delta_detector[set].streaming) {
        blocks[set][way].rrpv = RRPV_MAX;
        blocks[set][way].ship_sig = sig;
        blocks[set][way].valid = true;
        return;
    }

    // SHiP vs RRIP: leader sets decide, others follow PSEL
    uint8_t ins_rrpv;
    if (leader_sets[set] == 1) { // SHiP leader
        ins_rrpv = (ship_table[ship_idx].counter >= SHIP_THRESHOLD) ? SRRIP_INSERT : BRRIP_INSERT;
    } else if (leader_sets[set] == 2) { // RRIP leader
        ins_rrpv = BRRIP_INSERT;
    } else {
        ins_rrpv = (PSEL >= PSEL_MAX/2) ?
            ((ship_table[ship_idx].counter >= SHIP_THRESHOLD) ? SRRIP_INSERT : BRRIP_INSERT)
            : BRRIP_INSERT;
    }
    blocks[set][way].rrpv = ins_rrpv;
    blocks[set][way].ship_sig = sig;
    blocks[set][way].valid = true;

    // PSEL update (misses in leader sets)
    if (leader_sets[set] == 1) {
        if (!hit && PSEL < PSEL_MAX) PSEL++;
    } else if (leader_sets[set] == 2) {
        if (!hit && PSEL > 0) PSEL--;
    }
}

// --- Print stats ---
void PrintStats() {
    uint64_t streaming_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; s++)
        if (delta_detector[s].streaming) streaming_sets++;
    std::cout << "SL-SDB: Streaming sets=" << streaming_sets << "/" << LLC_SETS << std::endl;
    std::cout << "SL-SDB: PSEL=" << PSEL << "/" << PSEL_MAX << std::endl;
    std::cout << "SL-SDB: Leader sets: SHiP=" << ship_leader_cnt << " RRIP=" << rrip_leader_cnt << std::endl;
}

// --- Print heartbeat stats ---
void PrintStats_Heartbeat() {
    // No periodic stats needed
}