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
#define SRRIP_INSERT 0
#define BRRIP_INSERT (RRPV_MAX-1)

// SHiP-lite parameters
#define SHIP_SIG_BITS 6
#define SHIP_TABLE_SIZE (1<<SHIP_SIG_BITS) // 64
#define SHIP_ENTRIES (LLC_SETS)            // 2048
#define SHIP_COUNTER_BITS 2
#define SHIP_MAX ((1<<SHIP_COUNTER_BITS)-1)
#define SHIP_THRESHOLD 1

// Set-dueling for SHiP vs BRRIP
#define NUM_LEADER_SETS 32
#define PSEL_BITS 10
#define PSEL_MAX ((1<<PSEL_BITS)-1)
#define PSEL_INIT (PSEL_MAX/2)

// Streaming detector parameters
#define STREAM_DELTA_BITS 2
#define STREAM_MAX ((1<<STREAM_DELTA_BITS)-1)
#define STREAM_DETECT_THRESH 2 // If counter saturates, treat as streaming

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

// Streaming detector: per-set last address and 2-bit streaming counter
std::vector<uint64_t> last_addr(LLC_SETS, 0);
std::vector<uint8_t> stream_cnt(LLC_SETS, 0);

// --- Helper: get PC signature ---
inline uint8_t get_ship_sig(uint64_t PC, uint32_t set) {
    return ((PC >> 2) ^ set) & (SHIP_TABLE_SIZE-1);
}

// --- Helper: get SHiP table index ---
inline uint32_t get_ship_idx(uint32_t set, uint8_t sig) {
    return (set * SHIP_TABLE_SIZE) + sig;
}

// --- Init ---
void InitReplacementState() {
    ship_leader_cnt = 0; brrip_leader_cnt = 0;
    for (uint32_t s = 0; s < LLC_SETS; s++) {
        for (uint32_t w = 0; w < LLC_WAYS; w++) {
            blocks[s][w] = {RRPV_MAX, 0, false};
        }
        leader_sets[s] = 0;
        last_addr[s] = 0;
        stream_cnt[s] = 0;
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
    // Streaming detector: if streaming detected, always evict LRU (highest RRPV)
    if (stream_cnt[set] >= STREAM_DETECT_THRESH) {
        uint32_t victim = 0;
        uint8_t max_rrpv = 0;
        for (uint32_t w = 0; w < LLC_WAYS; w++) {
            if (blocks[set][w].valid && blocks[set][w].rrpv >= max_rrpv) {
                max_rrpv = blocks[set][w].rrpv;
                victim = w;
            }
        }
        return victim;
    }
    // Otherwise, standard RRIP victim selection
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
    // --- Streaming detector update ---
    uint64_t prev_addr = last_addr[set];
    last_addr[set] = paddr;
    if (prev_addr != 0) {
        int64_t delta = (int64_t)paddr - (int64_t)prev_addr;
        // Detect monotonic forward stride (positive, small stride)
        if (delta > 0 && delta < 1024) {
            if (stream_cnt[set] < STREAM_MAX) stream_cnt[set]++;
        } else {
            if (stream_cnt[set] > 0) stream_cnt[set]--;
        }
    }

    // --- SHiP-lite update ---
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

    // --- Streaming bypass logic ---
    if (stream_cnt[set] >= STREAM_DETECT_THRESH) {
        // Streaming detected: bypass insertion (do not allocate block)
        blocks[set][way].valid = false;
        return;
    }

    // --- Decide insertion depth ---
    uint8_t ins_rrpv;
    bool ship_predicts_reuse = (ship_table[ship_idx].counter >= SHIP_THRESHOLD);

    // Leader sets: SHiP vs BRRIP, others follow PSEL
    if (leader_sets[set] == 1) { // SHiP leader
        ins_rrpv = ship_predicts_reuse ? SRRIP_INSERT : BRRIP_INSERT;
    } else if (leader_sets[set] == 2) { // BRRIP leader
        ins_rrpv = BRRIP_INSERT;
    } else {
        if (PSEL >= PSEL_MAX/2) {
            ins_rrpv = ship_predicts_reuse ? SRRIP_INSERT : BRRIP_INSERT;
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
        if (stream_cnt[s] >= STREAM_DETECT_THRESH)
            streaming_sets++;
    }
    std::cout << "SL-SDB: Streaming sets=" << streaming_sets << "/" << LLC_SETS << std::endl;
    std::cout << "SL-SDB: PSEL=" << PSEL << "/" << PSEL_MAX << std::endl;
    std::cout << "SL-SDB: Leader sets: SHiP=" << ship_leader_cnt << " BRRIP=" << brrip_leader_cnt << std::endl;
}

// --- Print heartbeat stats ---
void PrintStats_Heartbeat() {
    // No periodic stats needed
}