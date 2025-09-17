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

// Streaming detector parameters
#define STREAM_DELTA_BITS 2
#define STREAM_MAX ((1<<STREAM_DELTA_BITS)-1)
#define STREAM_DETECT_THRESH 2 // If counter saturates, treat as streaming

// Dead block predictor
#define DEAD_BITS 2
#define DEAD_MAX ((1<<DEAD_BITS)-1)
#define DEAD_THRESHOLD 2
#define DECAY_PERIOD 8192 // Decay every N accesses

struct block_state_t {
    uint8_t dead_ctr; // 2 bits: dead block counter
    uint8_t rrpv;     // 2 bits: RRIP value
    bool valid;
    uint64_t tag;
};
std::vector<std::vector<block_state_t>> blocks(LLC_SETS, std::vector<block_state_t>(LLC_WAYS));

// DIP leader sets
std::vector<uint8_t> leader_sets(LLC_SETS, 0); // 0: follower, 1: LIP leader, 2: BIP leader
uint32_t lip_leader_cnt = 0, bip_leader_cnt = 0;
uint32_t PSEL = PSEL_INIT;

// Streaming detector: per-set last address and 2-bit streaming counter
std::vector<uint64_t> last_addr(LLC_SETS, 0);
std::vector<uint8_t> stream_cnt(LLC_SETS, 0);

// Dead block decay counter
uint64_t global_access_ctr = 0;

// --- Init ---
void InitReplacementState() {
    lip_leader_cnt = 0; bip_leader_cnt = 0;
    for (uint32_t s = 0; s < LLC_SETS; s++) {
        for (uint32_t w = 0; w < LLC_WAYS; w++) {
            blocks[s][w] = {0, 3, false, 0};
        }
        leader_sets[s] = 0;
        last_addr[s] = 0;
        stream_cnt[s] = 0;
    }
    // DIP: randomly assign leader sets
    for (uint32_t i = 0; i < NUM_LEADER_SETS; i++) {
        uint32_t lip_set = (i * 37) % LLC_SETS;
        uint32_t bip_set = (i * 71 + 13) % LLC_SETS;
        if (leader_sets[lip_set] == 0) { leader_sets[lip_set] = 1; lip_leader_cnt++; }
        if (leader_sets[bip_set] == 0) { leader_sets[bip_set] = 2; bip_leader_cnt++; }
    }
    PSEL = PSEL_INIT;
    global_access_ctr = 0;
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
            if (blocks[set][w].rrpv == 3)
                return w;
        }
        for (uint32_t w = 0; w < LLC_WAYS; w++) {
            if (blocks[set][w].rrpv < 3)
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
    global_access_ctr++;

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

    // --- Dead block predictor update ---
    if (hit) {
        blocks[set][way].dead_ctr = 0; // Reset on hit
        blocks[set][way].rrpv = 0;     // MRU on hit
        blocks[set][way].valid = true;
        blocks[set][way].tag = paddr >> 6;
        return;
    }

    // On miss: increment dead counter for victim block
    if (blocks[set][way].valid) {
        if (blocks[set][way].dead_ctr < DEAD_MAX)
            blocks[set][way].dead_ctr++;
    }

    // --- Streaming bypass logic ---
    if (stream_cnt[set] >= STREAM_DETECT_THRESH) {
        // Streaming detected: bypass insertion (do not allocate block)
        blocks[set][way].valid = false;
        return;
    }

    // --- DIP insertion policy ---
    bool is_dead = (blocks[set][way].dead_ctr >= DEAD_THRESHOLD);

    uint8_t ins_rrpv;
    if (is_dead) {
        ins_rrpv = 3; // Insert at LRU if predicted dead
    } else {
        // DIP: LIP vs BIP
        if (leader_sets[set] == 1) { // LIP leader
            ins_rrpv = 3; // LIP: always LRU
        } else if (leader_sets[set] == 2) { // BIP leader
            static uint32_t bip_ctr = 0;
            if ((bip_ctr++ & 0x1F) == 0) // 1/32 times MRU
                ins_rrpv = 0;
            else
                ins_rrpv = 3;
        } else {
            if (PSEL >= PSEL_MAX/2) {
                ins_rrpv = 3; // LIP
            } else {
                static uint32_t bip_ctr_f = 0;
                if ((bip_ctr_f++ & 0x1F) == 0)
                    ins_rrpv = 0;
                else
                    ins_rrpv = 3;
            }
        }
    }
    blocks[set][way].rrpv = ins_rrpv;
    blocks[set][way].dead_ctr = 0;
    blocks[set][way].valid = true;
    blocks[set][way].tag = paddr >> 6;

    // DIP PSEL update (misses in leader sets)
    if (leader_sets[set] == 1) {
        if (!hit && PSEL < PSEL_MAX) PSEL++;
    } else if (leader_sets[set] == 2) {
        if (!hit && PSEL > 0) PSEL--;
    }

    // --- Periodic dead counter decay ---
    if ((global_access_ctr & (DECAY_PERIOD-1)) == 0) {
        for (uint32_t s = 0; s < LLC_SETS; s++) {
            for (uint32_t w = 0; w < LLC_WAYS; w++) {
                if (blocks[s][w].dead_ctr > 0)
                    blocks[s][w].dead_ctr--;
            }
        }
    }
}

// --- Print stats ---
void PrintStats() {
    uint64_t streaming_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; s++) {
        if (stream_cnt[s] >= STREAM_DETECT_THRESH)
            streaming_sets++;
    }
    std::cout << "DIP-LIP+SDBP: Streaming sets=" << streaming_sets << "/" << LLC_SETS << std::endl;
    std::cout << "DIP-LIP+SDBP: PSEL=" << PSEL << "/" << PSEL_MAX << std::endl;
    std::cout << "DIP-LIP+SDBP: Leader sets: LIP=" << lip_leader_cnt << " BIP=" << bip_leader_cnt << std::endl;
}

// --- Print heartbeat stats ---
void PrintStats_Heartbeat() {
    // No periodic stats needed
}