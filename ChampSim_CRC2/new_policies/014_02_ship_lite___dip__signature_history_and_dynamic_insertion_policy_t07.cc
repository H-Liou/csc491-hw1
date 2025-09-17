#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- DIP Metadata ---
static uint8_t is_bip_leader[LLC_SETS]; // 1 bit per set (LRU/BIP leader sets)
static uint16_t psel = 512; // 10 bits, mid-value

// --- SHiP-lite Metadata ---
#define SIG_TABLE_SIZE 4096
static uint8_t reuse_counter[SIG_TABLE_SIZE]; // 2 bits per signature (PC)
static uint16_t pc_signature[LLC_SETS][LLC_WAYS]; // 12 bits per line

// --- RRPV bits ---
static uint8_t rrpv[LLC_SETS][LLC_WAYS]; // 2 bits per line

// --- Initialization ---
void InitReplacementState() {
    memset(is_bip_leader, 0, sizeof(is_bip_leader));
    memset(rrpv, 3, sizeof(rrpv));
    memset(reuse_counter, 0, sizeof(reuse_counter));
    memset(pc_signature, 0, sizeof(pc_signature));

    // DIP: Assign 32 leader sets to LRU (low indices), 32 to BIP (high indices)
    for (uint32_t i = 0; i < LLC_SETS; ++i) {
        if (i < 32) is_bip_leader[i] = 0; // LRU leader
        else if (i >= LLC_SETS - 32) is_bip_leader[i] = 1; // BIP leader
        // else: follower
    }
    psel = 512;
}

// --- Helper: get compact PC signature ---
inline uint16_t GetSignature(uint64_t PC) {
    return (uint16_t)((PC >> 2) & (SIG_TABLE_SIZE - 1));
}

// --- Find victim: standard RRIP + dead-block hint via SHiP ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Prefer lines whose SHiP counter is zero (likely dead)
    for (uint32_t way = 0; way < LLC_WAYS; ++way) {
        uint16_t sig = pc_signature[set][way];
        if (reuse_counter[sig] == 0)
            return way;
    }
    // Otherwise, use RRIP victim selection
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] < 3) ++rrpv[set][way];
    }
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
    uint16_t sig = GetSignature(PC);

    // On hit: promote to MRU, increment outcome counter
    if (hit) {
        rrpv[set][way] = 0;
        if (reuse_counter[sig] < 3) ++reuse_counter[sig];
        return;
    } else {
        // On eviction, decrement counter for the signature of the victim
        uint16_t victim_sig = pc_signature[set][way];
        if (reuse_counter[victim_sig] > 0) --reuse_counter[victim_sig];
    }

    // Record signature for new line
    pc_signature[set][way] = sig;

    // DIP: Choose insertion depth
    uint8_t insert_rrpv = 2; // default: somewhat distant
    bool bip_insert = false;
    if (is_bip_leader[set] == 1) {
        // BIP leader: insert distant most times, MRU only 1/32
        bip_insert = ((rand() & 31) == 0);
        insert_rrpv = bip_insert ? 0 : 2;
    } else if (is_bip_leader[set] == 0) {
        // LRU leader: always insert MRU
        insert_rrpv = 0;
    } else {
        // Follower: PSEL controls
        if (psel >= 512) {
            // LRU preferred
            insert_rrpv = 0;
        } else {
            bip_insert = ((rand() & 31) == 0);
            insert_rrpv = bip_insert ? 0 : 2;
        }
    }

    // SHiP: if signature has low reuse, always insert distant
    if (reuse_counter[sig] <= 1)
        insert_rrpv = 2;

    rrpv[set][way] = insert_rrpv;

    // DIP: update PSEL based on misses in leader sets
    if (is_bip_leader[set] == 1 && !hit) {
        if (psel > 0) --psel;
    } else if (is_bip_leader[set] == 0 && !hit) {
        if (psel < 1023) ++psel;
    }
}

// --- Print statistics ---
void PrintStats() {
    std::cout << "SHiP-Lite + DIP Policy\n";
    std::cout << "PSEL: " << psel << std::endl;
    // Print SHiP counter histogram
    uint32_t hist[4] = {0,0,0,0};
    for (uint32_t i = 0; i < SIG_TABLE_SIZE; ++i)
        hist[reuse_counter[i]]++;
    std::cout << "SHiP signature histogram: ";
    for (int i=0; i<4; ++i) std::cout << hist[i] << " ";
    std::cout << std::endl;
}

// --- Heartbeat stats ---
void PrintStats_Heartbeat() {
    // No-op for brevity
}