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
#define BIP_PROB 32 // Insert at MRU 1/32 times in BIP

// RRIP parameters
#define RRPV_BITS 2
#define RRPV_MAX ((1<<RRPV_BITS)-1)
#define LRU_INSERT RRPV_MAX       // LIP: insert at LRU (max RRPV)
#define MRU_INSERT 0              // BIP: insert at MRU (min RRPV)

// Streaming detector parameters
#define STREAM_DELTA_BITS 2
#define STREAM_MAX ((1<<STREAM_DELTA_BITS)-1)
#define STREAM_DETECT_THRESH 2 // If counter saturates, treat as streaming

// Block state
struct block_state_t {
    uint8_t rrpv;      // 2 bits: RRIP value
    bool valid;
};
std::vector<std::vector<block_state_t>> blocks(LLC_SETS, std::vector<block_state_t>(LLC_WAYS));

// Set-dueling leader sets
std::vector<uint8_t> leader_sets(LLC_SETS, 0); // 0: follower, 1: LIP leader, 2: BIP leader
uint32_t lip_leader_cnt = 0, bip_leader_cnt = 0;
uint32_t PSEL = PSEL_INIT;

// Streaming detector: per-set last address and 2-bit streaming counter
std::vector<uint64_t> last_addr(LLC_SETS, 0);
std::vector<uint8_t> stream_cnt(LLC_SETS, 0);

// --- Init ---
void InitReplacementState() {
    lip_leader_cnt = 0; bip_leader_cnt = 0;
    for (uint32_t s = 0; s < LLC_SETS; s++) {
        for (uint32_t w = 0; w < LLC_WAYS; w++) {
            blocks[s][w] = {RRPV_MAX, false};
        }
        leader_sets[s] = 0;
        last_addr[s] = 0;
        stream_cnt[s] = 0;
    }
    for (uint32_t i = 0; i < NUM_LEADER_SETS; i++) {
        uint32_t lip_set = (i * 37) % LLC_SETS;
        uint32_t bip_set = (i * 71 + 13) % LLC_SETS;
        if (leader_sets[lip_set] == 0) { leader_sets[lip_set] = 1; lip_leader_cnt++; }
        if (leader_sets[bip_set] == 0) { leader_sets[bip_set] = 2; bip_leader_cnt++; }
    }
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

    // On hit: promote block to MRU
    if (hit) {
        blocks[set][way].rrpv = MRU_INSERT;
        blocks[set][way].valid = true;
        return;
    }

    // Streaming bypass logic: don't allocate block if streaming detected
    if (stream_cnt[set] >= STREAM_DETECT_THRESH) {
        blocks[set][way].valid = false;
        return;
    }

    // --- Decide insertion depth ---
    uint8_t ins_rrpv;
    static uint32_t bip_ctr = 0;

    if (leader_sets[set] == 1) { // LIP leader
        ins_rrpv = LRU_INSERT;
    } else if (leader_sets[set] == 2) { // BIP leader
        // Insert at MRU only 1/BIP_PROB times
        if ((bip_ctr++ % BIP_PROB) == 0)
            ins_rrpv = MRU_INSERT;
        else
            ins_rrpv = LRU_INSERT;
    } else {
        // Follower sets: select policy by PSEL
        if (PSEL >= PSEL_MAX/2) {
            // Use BIP
            if ((bip_ctr++ % BIP_PROB) == 0)
                ins_rrpv = MRU_INSERT;
            else
                ins_rrpv = LRU_INSERT;
        } else {
            // Use LIP
            ins_rrpv = LRU_INSERT;
        }
    }
    blocks[set][way].rrpv = ins_rrpv;
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
    std::cout << "DIP-SDB: Streaming sets=" << streaming_sets << "/" << LLC_SETS << std::endl;
    std::cout << "DIP-SDB: PSEL=" << PSEL << "/" << PSEL_MAX << std::endl;
    std::cout << "DIP-SDB: Leader sets: LIP=" << lip_leader_cnt << " BIP=" << bip_leader_cnt << std::endl;
}

// --- Print heartbeat stats ---
void PrintStats_Heartbeat() {
    // No periodic stats needed
}