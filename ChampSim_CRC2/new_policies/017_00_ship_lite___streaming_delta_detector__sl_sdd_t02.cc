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
#define DELTA_HISTORY_LEN 4 // 4 recent deltas per set
#define DELTA_BITS 16       // 16 bits per delta
#define DELTA_STREAM_TOL 2  // Allow 2 mismatches for streaming

// Set-dueling for SHiP vs BRRIP
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

// Set-dueling leader sets
std::vector<uint8_t> leader_sets(LLC_SETS, 0); // 0: follower, 1: SHiP leader, 2: BRRIP leader
uint32_t ship_leader_cnt = 0, brrip_leader_cnt = 0;
uint32_t PSEL = PSEL_INIT;

// Streaming delta detector: per-set address history and delta history
struct delta_hist_t {
    uint64_t last_addr;
    uint16_t deltas[DELTA_HISTORY_LEN];
    uint8_t idx;
    bool initialized;
};
std::vector<delta_hist_t> delta_histories(LLC_SETS);

// --- Helper: get PC signature ---
inline uint8_t get_ship_sig(uint64_t PC, uint32_t set) {
    return ((PC >> 2) ^ set) & (SHIP_TABLE_SIZE-1);
}

// --- Helper: get SHiP table index ---
inline uint32_t get_ship_idx(uint32_t set, uint8_t sig) {
    return (set * SHIP_TABLE_SIZE) + sig;
}

// --- Streaming detector: update delta history and check for streaming ---
bool is_streaming(uint32_t set, uint64_t paddr) {
    delta_hist_t &dh = delta_histories[set];
    if (!dh.initialized) {
        dh.last_addr = paddr;
        std::fill(std::begin(dh.deltas), std::end(dh.deltas), 0);
        dh.idx = 0;
        dh.initialized = true;
        return false;
    }
    uint64_t delta = paddr - dh.last_addr;
    dh.deltas[dh.idx] = (uint16_t)(delta & 0xFFFF);
    dh.idx = (dh.idx + 1) % DELTA_HISTORY_LEN;
    dh.last_addr = paddr;

    // Check for near-monotonic streaming: all deltas equal (allow DELTA_STREAM_TOL mismatches)
    uint16_t ref_delta = dh.deltas[0];
    uint8_t mismatches = 0;
    for (uint8_t i = 1; i < DELTA_HISTORY_LEN; i++) {
        if (dh.deltas[i] != ref_delta) mismatches++;
    }
    return (mismatches <= DELTA_STREAM_TOL && ref_delta != 0);
}

// --- Init ---
void InitReplacementState() {
    ship_leader_cnt = 0; brrip_leader_cnt = 0;
    for (uint32_t s = 0; s < LLC_SETS; s++) {
        for (uint32_t w = 0; w < LLC_WAYS; w++) {
            blocks[s][w] = {RRPV_MAX, 0, false};
        }
        leader_sets[s] = 0;
        delta_histories[s] = {0, {0,0,0,0}, 0, false};
    }
    for (uint32_t i = 0; i < NUM_LEADER_SETS; i++) {
        uint32_t ship_set = (i * 37) % LLC_SETS;
        uint32_t brrip_set = (i * 71 + 13) % LLC_SETS;
        if (leader_sets[ship_set] == 0) { leader_sets[ship_set] = 1; ship_leader_cnt++; }
        if (leader_sets[brrip_set] == 0) { leader_sets[brrip_set] = 2; brrip_leader_cnt++; }
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
    bool streaming = is_streaming(set, paddr);

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

    // Decide insertion depth
    uint8_t ins_rrpv;
    bool ship_predicts_reuse = (ship_table[ship_idx].counter >= SHIP_THRESHOLD);

    // Leader sets: SHiP vs BRRIP, others follow PSEL
    if (leader_sets[set] == 1) { // SHiP leader
        if (streaming)
            ins_rrpv = BRRIP_INSERT;
        else
            ins_rrpv = ship_predicts_reuse ? SRRIP_INSERT : BRRIP_INSERT;
    } else if (leader_sets[set] == 2) { // BRRIP leader
        ins_rrpv = BRRIP_INSERT;
    } else {
        if (PSEL >= PSEL_MAX/2) {
            ins_rrpv = streaming ? BRRIP_INSERT : (ship_predicts_reuse ? SRRIP_INSERT : BRRIP_INSERT);
        } else {
            ins_rrpv = BRRIP_INSERT;
        }
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
    for (uint32_t s = 0; s < LLC_SETS; s++) {
        bool stream = false;
        for (uint8_t i = 1; i < DELTA_HISTORY_LEN; i++) {
            if (delta_histories[s].deltas[i] != delta_histories[s].deltas[0])
                stream = true;
        }
        if (stream) streaming_sets++;
    }
    std::cout << "SL-SDD: Streaming sets=" << streaming_sets << "/" << LLC_SETS << std::endl;
    std::cout << "SL-SDD: PSEL=" << PSEL << "/" << PSEL_MAX << std::endl;
    std::cout << "SL-SDD: Leader sets: SHiP=" << ship_leader_cnt << " BRRIP=" << brrip_leader_cnt << std::endl;
}

// --- Print heartbeat stats ---
void PrintStats_Heartbeat() {
    // No periodic stats needed
}