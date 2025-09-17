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

// Streaming detector
#define STREAM_DELTA_BITS 2
#define STREAM_MAX ((1<<STREAM_DELTA_BITS)-1)
#define STREAM_DETECT_THRESH 2

// Dead-block counter
#define DEAD_BITS 2
#define DEAD_MAX ((1<<DEAD_BITS)-1)
#define DEAD_DEAD_THRESH 2  // If counter saturates, treat as dead

// Per-block state
struct block_state_t {
    bool valid;
    uint8_t dead_cnt; // 2 bits
};
std::vector<std::vector<block_state_t>> blocks(LLC_SETS, std::vector<block_state_t>(LLC_WAYS));

// RRIP for victim selection
std::vector<std::vector<uint8_t>> rrpv(LLC_SETS, std::vector<uint8_t>(LLC_WAYS, 3)); // 2-bit, init to 3

// Leader set tracking: 0=follower, 1=LIP leader, 2=BIP leader
std::vector<uint8_t> leader_sets(LLC_SETS, 0);
uint32_t lip_leader_cnt = 0, bip_leader_cnt = 0;
uint32_t PSEL = PSEL_INIT;

// Streaming detector: per-set last address and counter
std::vector<uint64_t> last_addr(LLC_SETS, 0);
std::vector<uint8_t> stream_cnt(LLC_SETS, 0);

// Heartbeat dead-block decay
uint64_t decay_tick = 0;
const uint64_t DECAY_PERIOD = 100000; // every 100K accesses

// --- Init ---
void InitReplacementState() {
    lip_leader_cnt = 0; bip_leader_cnt = 0;
    for (uint32_t s = 0; s < LLC_SETS; s++) {
        for (uint32_t w = 0; w < LLC_WAYS; w++) {
            blocks[s][w] = {false, 0};
            rrpv[s][w] = 3;
        }
        leader_sets[s] = 0;
        last_addr[s] = 0;
        stream_cnt[s] = 0;
    }
    // Leader sets: spread LIP/BIP across sets
    for (uint32_t i = 0; i < NUM_LEADER_SETS; i++) {
        uint32_t lip_set = (i * 41) % LLC_SETS;
        uint32_t bip_set = (i * 67 + 17) % LLC_SETS;
        if (leader_sets[lip_set] == 0) { leader_sets[lip_set] = 1; lip_leader_cnt++; }
        if (leader_sets[bip_set] == 0) { leader_sets[bip_set] = 2; bip_leader_cnt++; }
    }
    PSEL = PSEL_INIT;
    decay_tick = 0;
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
    // Streaming detected: always evict block at LRU
    if (stream_cnt[set] >= STREAM_DETECT_THRESH) {
        uint32_t victim = 0;
        uint8_t max_rrpv = 0;
        for (uint32_t w = 0; w < LLC_WAYS; w++) {
            if (blocks[set][w].valid && rrpv[set][w] >= max_rrpv) {
                max_rrpv = rrpv[set][w];
                victim = w;
            }
        }
        return victim;
    }
    // Otherwise, RRIP: evict highest RRPV
    while (true) {
        for (uint32_t w = 0; w < LLC_WAYS; w++) {
            if (blocks[set][w].valid && rrpv[set][w] == 3)
                return w;
        }
        for (uint32_t w = 0; w < LLC_WAYS; w++) {
            if (rrpv[set][w] < 3)
                rrpv[set][w]++;
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
    decay_tick++;
    // --- Streaming detector update ---
    uint64_t prev_addr = last_addr[set];
    last_addr[set] = paddr;
    if (prev_addr != 0) {
        int64_t delta = (int64_t)paddr - (int64_t)prev_addr;
        // Detect monotonic forward stride
        if (delta > 0 && delta < 1024) {
            if (stream_cnt[set] < STREAM_MAX) stream_cnt[set]++;
        } else {
            if (stream_cnt[set] > 0) stream_cnt[set]--;
        }
    }
    // --- Dead-block update ---
    if (hit) {
        blocks[set][way].dead_cnt = 0; // reset on reuse
        rrpv[set][way] = 0; // promote to MRU
        blocks[set][way].valid = true;
        return;
    }
    // On miss, victim block: increment dead counter
    if (blocks[set][way].valid) {
        if (blocks[set][way].dead_cnt < DEAD_MAX)
            blocks[set][way].dead_cnt++;
    }
    // --- Streaming bypass ---
    if (stream_cnt[set] >= STREAM_DETECT_THRESH) {
        // Streaming: bypass (do not allocate block)
        blocks[set][way].valid = false;
        rrpv[set][way] = 3;
        blocks[set][way].dead_cnt = 0;
        return;
    }
    // --- Dead-block bypass ---
    if (blocks[set][way].dead_cnt >= DEAD_DEAD_THRESH) {
        // Dead predicted: bypass allocation
        blocks[set][way].valid = false;
        rrpv[set][way] = 3;
        blocks[set][way].dead_cnt = 0;
        return;
    }
    // --- DIP: insertion depth control ---
    uint8_t ins_rrpv;
    bool use_lip = false;
    if (leader_sets[set] == 1) { // LIP leader
        use_lip = true;
    } else if (leader_sets[set] == 2) { // BIP leader
        use_lip = false;
    } else {
        use_lip = (PSEL >= PSEL_MAX/2);
    }
    if (use_lip) {
        ins_rrpv = 3; // LIP: always insert at LRU
    } else {
        // BIP: insert at MRU with 1/32 probability, else LRU
        static uint32_t bip_ctr = 0;
        if ((bip_ctr++ % 32) == 0)
            ins_rrpv = 0;
        else
            ins_rrpv = 3;
    }
    blocks[set][way].valid = true;
    blocks[set][way].dead_cnt = 0;
    rrpv[set][way] = ins_rrpv;
    // --- DIP leader set update ---
    if (leader_sets[set] == 1) { // LIP leader
        if (!hit && PSEL < PSEL_MAX) PSEL++;
    } else if (leader_sets[set] == 2) { // BIP leader
        if (!hit && PSEL > 0) PSEL--;
    }
    // --- Periodic dead counter decay ---
    if (decay_tick % DECAY_PERIOD == 0) {
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
    uint64_t streaming_sets = 0, dead_blocks = 0;
    for (uint32_t s = 0; s < LLC_SETS; s++) {
        if (stream_cnt[s] >= STREAM_DETECT_THRESH)
            streaming_sets++;
        for (uint32_t w = 0; w < LLC_WAYS; w++) {
            if (blocks[s][w].dead_cnt >= DEAD_DEAD_THRESH)
                dead_blocks++;
        }
    }
    std::cout << "DIP-LIP-SDB: Streaming sets=" << streaming_sets << "/" << LLC_SETS << std::endl;
    std::cout << "DIP-LIP-SDB: Dead blocks=" << dead_blocks << "/" << (LLC_SETS*LLC_WAYS) << std::endl;
    std::cout << "DIP-LIP-SDB: PSEL=" << PSEL << "/" << PSEL_MAX << std::endl;
    std::cout << "DIP-LIP-SDB: Leader sets: LIP=" << lip_leader_cnt << " BIP=" << bip_leader_cnt << std::endl;
}

// --- Print heartbeat stats ---
void PrintStats_Heartbeat() {
    // No periodic stats needed
}