#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// DRRIP parameters
#define RRPV_BITS 2
#define RRPV_MAX 3
#define PSEL_BITS 10
#define PSEL_MAX ((1 << PSEL_BITS) - 1)

// Dead-block predictor parameters
#define DEAD_COUNTER_BITS 2         // 2-bit per-block reuse counter
#define DEAD_COUNTER_MAX 3
#define DEAD_DECAY_PERIOD 4096      // Decay every N accesses

// Set-dueling for DRRIP
#define DUELING_LEADER_SETS 32
#define SRRIP_LEADER_SET_MASK 0x1F        // First 32 sets as SRRIP leaders
#define BRRIP_LEADER_SET_MASK 0x20        // Next 32 sets as BRRIP leaders

// Metadata
std::vector<uint8_t> block_rrpv;         // Per-block RRPV
std::vector<uint8_t> block_deadctr;      // Per-block dead-block predictor (2 bits)
uint16_t psel_counter = PSEL_MAX / 2;    // DRRIP PSEL (10 bits)
std::vector<uint8_t> set_type;           // Per-set: 0=normal, 1=SRRIP leader, 2=BRRIP leader

// Stats
uint64_t access_counter = 0;
uint64_t hits = 0;
uint64_t dead_bypass = 0;
uint64_t dead_fills = 0;
uint64_t dead_evictions = 0;

// Helper: get block meta index
inline size_t get_block_idx(uint32_t set, uint32_t way) {
    return set * LLC_WAYS + way;
}

// Initialization
void InitReplacementState() {
    block_rrpv.resize(LLC_SETS * LLC_WAYS, RRPV_MAX);
    block_deadctr.resize(LLC_SETS * LLC_WAYS, 0);
    set_type.resize(LLC_SETS, 0);
    // Set leader sets for set-dueling
    for (uint32_t s = 0; s < LLC_SETS; s++) {
        if ((s & SRRIP_LEADER_SET_MASK) == s)
            set_type[s] = 1; // SRRIP leader
        else if ((s & BRRIP_LEADER_SET_MASK) == s)
            set_type[s] = 2; // BRRIP leader
        else
            set_type[s] = 0; // Follower
    }
    psel_counter = PSEL_MAX / 2;
    access_counter = 0;
    hits = 0;
    dead_bypass = 0;
    dead_fills = 0;
    dead_evictions = 0;
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
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        size_t idx = get_block_idx(set, way);
        if (block_rrpv[idx] == RRPV_MAX)
            return way;
    }
    // If no victim, increment all RRPVs and retry
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        size_t idx = get_block_idx(set, way);
        if (block_rrpv[idx] < RRPV_MAX)
            block_rrpv[idx]++;
    }
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        size_t idx = get_block_idx(set, way);
        if (block_rrpv[idx] == RRPV_MAX)
            return way;
    }
    // Fallback
    return 0;
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
    access_counter++;

    size_t idx = get_block_idx(set, way);

    // Periodic decay of dead-block counters
    if ((access_counter & (DEAD_DECAY_PERIOD - 1)) == 0) {
        for (size_t i = 0; i < block_deadctr.size(); i++) {
            if (block_deadctr[i] > 0)
                block_deadctr[i]--;
        }
    }

    // On hit: promote to MRU (RRPV=0), increment dead-block counter
    if (hit) {
        hits++;
        block_rrpv[idx] = 0;
        if (block_deadctr[idx] < DEAD_COUNTER_MAX)
            block_deadctr[idx]++;
        return;
    }

    // On fill: Dead-block predictor guides insertion depth/bypass
    if (block_deadctr[idx] == 0) {
        // Dead predicted: streaming or pointer-chasing
        // Insert at distant RRPV or bypass with probability
        block_rrpv[idx] = RRPV_MAX;
        dead_fills++;
        // Optional: probabilistic bypass (e.g., 1/4 chance)
        // if ((access_counter & 0x3) == 0) {
        //     dead_bypass++;
        //     return; // Bypass fill
        // }
    } else {
        // Not dead: use DRRIP insertion policy
        uint8_t ins_rrpv = RRPV_MAX; // default distant
        if (set_type[set] == 1) { // SRRIP leader
            ins_rrpv = 2; // insert at RRPV=2
        } else if (set_type[set] == 2) { // BRRIP leader
            ins_rrpv = (rand() % 32 == 0) ? 2 : 3; // 1/32 at RRPV=2, else RRPV=3
        } else {
            // Follower: choose policy per PSEL
            if (psel_counter >= (PSEL_MAX / 2))
                ins_rrpv = 2; // SRRIP
            else
                ins_rrpv = (rand() % 32 == 0) ? 2 : 3; // BRRIP
        }
        block_rrpv[idx] = ins_rrpv;
    }

    // On eviction: train DRRIP (leader sets only)
    if (victim_addr != 0) {
        size_t victim_idx = get_block_idx(set, way);
        // If victim is in a leader set, update PSEL
        if (set_type[set] == 1) { // SRRIP leader set
            // If victim not reused (RRPV==MAX), increment PSEL (SRRIP better)
            if (block_rrpv[victim_idx] == RRPV_MAX && psel_counter < PSEL_MAX)
                psel_counter++;
        } else if (set_type[set] == 2) { // BRRIP leader set
            // If victim not reused, decrement PSEL (BRRIP worse)
            if (block_rrpv[victim_idx] == RRPV_MAX && psel_counter > 0)
                psel_counter--;
        }
        // Dead-block predictor: if block evicted without being reused, reset counter
        if (block_rrpv[victim_idx] == RRPV_MAX) {
            block_deadctr[victim_idx] = 0;
            dead_evictions++;
        }
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "DRRIP + Dead-Block Predictor Hybrid Policy\n";
    std::cout << "Total accesses: " << access_counter << "\n";
    std::cout << "Hits: " << hits << "\n";
    std::cout << "Dead-fills: " << dead_fills << "\n";
    std::cout << "Dead-block evictions: " << dead_evictions << "\n";
    std::cout << "DRRIP PSEL value: " << psel_counter << "\n";
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    std::cout << "DRRIP+DeadBlock heartbeat: accesses=" << access_counter
              << ", hits=" << hits
              << ", dead-fills=" << dead_fills
              << ", dead-evict=" << dead_evictions << "\n";
}