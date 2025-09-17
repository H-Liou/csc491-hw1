#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- DIP: Set-dueling between LRU and BIP ---
#define NUM_LEADER_SETS 64
#define PSEL_BITS 8
uint8_t is_leader_set[LLC_SETS]; // 1: LRU leader, 2: BIP leader, 0: follower
uint8_t PSEL = (1 << (PSEL_BITS - 1)); // 8-bit saturating counter

// --- Per-block LRU stack position (0=MRU,15=LRU) ---
uint8_t lru_stack[LLC_SETS][LLC_WAYS];

// --- SHiP-Lite: 5-bit signature per block, 2-bit reuse counter per signature ---
#define SHIP_SIG_BITS 5
#define SHIP_SIG_ENTRIES (1 << SHIP_SIG_BITS)
uint8_t ship_reuse_ctr[SHIP_SIG_ENTRIES]; // 2-bit counters
uint8_t ship_sig[LLC_SETS][LLC_WAYS]; // signature per block

// --- Streaming detector: 2-bit per set, last address/delta per set ---
uint8_t stream_ctr[LLC_SETS];
uint64_t last_addr[LLC_SETS];
uint64_t last_delta[LLC_SETS];

// --- For periodic SHiP counter decay ---
uint64_t access_counter = 0;
const uint64_t DECAY_PERIOD = 100000;

// --- Initialization ---
void InitReplacementState() {
    memset(lru_stack, 0, sizeof(lru_stack));
    memset(ship_reuse_ctr, 1, sizeof(ship_reuse_ctr)); // start neutral
    memset(ship_sig, 0, sizeof(ship_sig));
    memset(stream_ctr, 0, sizeof(stream_ctr));
    memset(last_addr, 0, sizeof(last_addr));
    memset(last_delta, 0, sizeof(last_delta));
    memset(is_leader_set, 0, sizeof(is_leader_set));
    // Assign leader sets for DIP
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i) {
        is_leader_set[i] = 1; // LRU leader
        is_leader_set[LLC_SETS - 1 - i] = 2; // BIP leader
    }
    PSEL = (1 << (PSEL_BITS - 1));
    access_counter = 0;
}

// --- Find victim: LRU ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Find LRU way (stack pos=15)
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (lru_stack[set][way] == LLC_WAYS - 1)
            return way;
    // Fallback
    return 0;
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

    // --- Streaming detector: update on fill (miss only) ---
    if (!hit) {
        uint64_t delta = (last_addr[set] == 0) ? 0 : (paddr - last_addr[set]);
        if (last_addr[set] != 0 && delta == last_delta[set] && delta != 0) {
            if (stream_ctr[set] < 3) stream_ctr[set]++;
        } else {
            if (stream_ctr[set] > 0) stream_ctr[set]--;
        }
        last_delta[set] = delta;
        last_addr[set] = paddr;
    }

    // --- SHiP-Lite signature ---
    uint8_t sig = (PC ^ (PC >> 5) ^ (set << 3)) & (SHIP_SIG_ENTRIES - 1);

    // --- On hit: update SHiP and LRU stack ---
    if (hit) {
        // SHiP: increment reuse counter, saturate to 3
        if (ship_reuse_ctr[sig] < 3) ship_reuse_ctr[sig]++;
        // Update block's signature
        ship_sig[set][way] = sig;
        // Move to MRU: increment stack pos for all < current, set this to 0
        uint8_t cur_pos = lru_stack[set][way];
        for (uint32_t w = 0; w < LLC_WAYS; ++w)
            if (lru_stack[set][w] < cur_pos)
                lru_stack[set][w]++;
        lru_stack[set][way] = 0;
        return;
    } else {
        // On miss (replacement/fill): update SHiP counter for evicted block
        uint8_t evict_sig = ship_sig[set][way];
        if (ship_reuse_ctr[evict_sig] > 0) ship_reuse_ctr[evict_sig]--;
    }

    // --- Streaming set: bypass insertion if streaming detected ---
    bool streaming = (stream_ctr[set] >= 2);
    if (streaming) {
        // Do not insert block, leave as invalid (simulate bypass)
        // Mark as LRU
        lru_stack[set][way] = LLC_WAYS - 1;
        ship_sig[set][way] = sig;
        // No need to update SHiP counter
        return;
    }

    // --- DIP: select insertion policy ---
    uint8_t insert_pos = 0; // MRU
    bool use_bip = false;
    if (is_leader_set[set] == 1) { // LRU leader
        use_bip = false;
    } else if (is_leader_set[set] == 2) { // BIP leader
        use_bip = true;
    } else { // follower
        use_bip = (PSEL < (1 << (PSEL_BITS - 1)));
    }

    // --- SHiP-Lite: bias insertion depth by signature reuse ---
    if (ship_reuse_ctr[sig] == 0) {
        insert_pos = LLC_WAYS - 2; // Insert close to LRU if signature is "dead"
    } else if (ship_reuse_ctr[sig] == 1) {
        insert_pos = LLC_WAYS / 2; // Insert mid-stack
    } else {
        insert_pos = 0; // Insert MRU
    }

    // --- BIP: insert MRU only on 1/32 fills ---
    if (use_bip) {
        if ((rand() % 32) != 0) insert_pos = LLC_WAYS - 2;
    }

    // --- Insert block at chosen stack position ---
    // First, increment all stack positions >= insert_pos
    for (uint32_t w = 0; w < LLC_WAYS; ++w)
        if (lru_stack[set][w] >= insert_pos)
            lru_stack[set][w]++;
    // Clamp values
    for (uint32_t w = 0; w < LLC_WAYS; ++w)
        if (lru_stack[set][w] >= LLC_WAYS)
            lru_stack[set][w] = LLC_WAYS - 1;
    // Set this block to insert_pos
    lru_stack[set][way] = insert_pos;
    ship_sig[set][way] = sig;

    // --- On eviction: update DIP PSEL for leader sets ---
    if (is_leader_set[set] == 1) { // LRU leader
        if (hit) {
            if (PSEL < ((1 << PSEL_BITS) - 1)) PSEL++;
        } else {
            if (PSEL > 0) PSEL--;
        }
    } else if (is_leader_set[set] == 2) { // BIP leader
        if (hit) {
            if (PSEL > 0) PSEL--;
        } else {
            if (PSEL < ((1 << PSEL_BITS) - 1)) PSEL++;
        }
    }

    // --- Periodic decay for SHiP counters ---
    if (access_counter % DECAY_PERIOD == 0) {
        for (uint32_t i = 0; i < SHIP_SIG_ENTRIES; ++i)
            if (ship_reuse_ctr[i] > 0)
                ship_reuse_ctr[i]--;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "SHiP-Lite + Streaming Bypass with DIP: Final statistics." << std::endl;
    // Streaming set count
    uint32_t streaming_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (stream_ctr[s] >= 2)
            streaming_sets++;
    std::cout << "Streaming sets at end: " << streaming_sets << "/" << LLC_SETS << std::endl;

    // SHiP counter histogram
    uint32_t dead = 0, weak = 0, strong = 0, total = 0;
    for (uint32_t i = 0; i < SHIP_SIG_ENTRIES; ++i) {
        if (ship_reuse_ctr[i] == 0) dead++;
        else if (ship_reuse_ctr[i] == 1) weak++;
        else strong++;
        total++;
    }
    std::cout << "SHiP counters: dead=" << dead << ", weak=" << weak << ", strong=" << strong << ", total=" << total << std::endl;
    std::cout << "PSEL value: " << (uint32_t)PSEL << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Optionally print streaming set count and SHiP reuse counter histogram
}