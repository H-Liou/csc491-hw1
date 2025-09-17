#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

//---------------------------------------------
// DIP set-dueling: 64 leader sets, 10-bit PSEL
#define NUM_LEADER_SETS 64
#define PSEL_MAX 1023
uint16_t PSEL = PSEL_MAX / 2; // 10-bit

uint8_t leader_set_type[NUM_LEADER_SETS]; // 0: LIP, 1: BIP
uint8_t set_type[LLC_SETS]; // 0: LIP, 1: BIP, 2: follower

//---------------------------------------------
// RRIP state: 2 bits per block
uint8_t rrpv[LLC_SETS][LLC_WAYS]; // 2 bits

//---------------------------------------------
// Streaming detector: 2 bits per set
uint8_t stream_ctr[LLC_SETS]; // 0–3
uint64_t last_addr[LLC_SETS];

//---------------------------------------------
// Signature-driven dead block predictor
// 4 bits per block for PC signature (lowest bits of PC)
// 2 bits per signature outcome table (256 entries)
#define SIG_BITS 4
#define SIG_TABLE_SIZE 256
uint8_t block_sig[LLC_SETS][LLC_WAYS]; // 4 bits per block
uint8_t sig_table[SIG_TABLE_SIZE];     // 2 bits per entry

//---------------------------------------------
// Per-block dead counter: 2 bits
uint8_t dead_ctr[LLC_SETS][LLC_WAYS]; // 0–3

//---------------------------------------------
// Helper: assign leader sets
void InitLeaderSets() {
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i)
        leader_set_type[i] = (i < NUM_LEADER_SETS / 2) ? 0 : 1;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        set_type[set] = (set < NUM_LEADER_SETS) ? leader_set_type[set] : 2;
}

//---------------------------------------------
// Initialize replacement state
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv));    // distant
    memset(stream_ctr, 0, sizeof(stream_ctr));
    memset(last_addr, 0, sizeof(last_addr));
    memset(block_sig, 0, sizeof(block_sig));
    memset(sig_table, 0, sizeof(sig_table));
    memset(dead_ctr, 0, sizeof(dead_ctr));
    InitLeaderSets();
    PSEL = PSEL_MAX / 2;
}

//---------------------------------------------
// Find victim in the set (prefer dead blocks, then RRIP)
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Prefer invalid block
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (!current_set[way].valid)
            return way;
    // Prefer dead block (dead_ctr == 0)
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (dead_ctr[set][way] == 0)
            return way;
    // RRIP victim: RRPV==3
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] < 3)
                rrpv[set][way]++;
    }
}

//---------------------------------------------
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
    //--- Streaming detector update ---
    uint64_t addr_delta = (last_addr[set] > 0) ? (paddr - last_addr[set]) : 0;
    last_addr[set] = paddr;
    if (addr_delta == 64 || addr_delta == -64) {
        if (stream_ctr[set] < 3) stream_ctr[set]++;
    } else {
        if (stream_ctr[set] > 0) stream_ctr[set]--;
    }

    //--- Signature extraction ---
    uint8_t sig = (PC ^ set) & 0xF; // 4 bits
    block_sig[set][way] = sig;
    uint32_t sig_idx = sig | ((set & 0xF) << 4); // 8 bits for diversity

    //--- Dead block predictor update ---
    if (hit) {
        rrpv[set][way] = 0; // protect
        if (dead_ctr[set][way] < 3) dead_ctr[set][way]++;
        // Signature outcome: positive
        if (sig_table[sig_idx] < 3) sig_table[sig_idx]++;
    } else {
        // On fill: streaming detected, bypass if strong
        if (stream_ctr[set] == 3) {
            // Streaming: bypass (insert at RRPV=3, mark as dead)
            rrpv[set][way] = 3;
            dead_ctr[set][way] = 0;
            return;
        }

        // DIP insertion depth selection
        uint8_t ins_rrpv = 3; // default distant (LIP)
        if (set_type[set] == 0) { // LIP: always insert at 3
            ins_rrpv = 3;
        } else if (set_type[set] == 1) { // BIP: insert at 2 only 1/32 times
            static uint32_t bip_tick = 0;
            ins_rrpv = (bip_tick++ % 32 == 0) ? 2 : 3;
        } else { // follower: use PSEL
            ins_rrpv = (PSEL >= PSEL_MAX / 2) ? 3 : ((rand() % 32 == 0) ? 2 : 3);
        }

        // Signature dead block bias: if outcome is cold, mark as dead
        uint8_t sig_val = sig_table[sig_idx];
        if (sig_val <= 1) {
            dead_ctr[set][way] = 0; // predicted dead
        } else {
            dead_ctr[set][way] = 2; // predicted live
        }

        rrpv[set][way] = ins_rrpv;
    }

    //--- Signature negative outcome (on eviction) ---
    if (!hit && victim_addr) {
        // Get victim block's signature
        uint32_t victim_set = set;
        uint32_t victim_way = way;
        uint8_t victim_sig = block_sig[victim_set][victim_way];
        uint32_t victim_sig_idx = victim_sig | ((victim_set & 0xF) << 4);
        if (sig_table[victim_sig_idx] > 0) sig_table[victim_sig_idx]--;
    }

    //--- DIP set-dueling feedback ---
    // Only update PSEL for leader sets
    if (!hit) return; // Only update on hit
    if (set < NUM_LEADER_SETS) {
        if (leader_set_type[set] == 0) { // LIP leader
            if (PSEL < PSEL_MAX) PSEL++;
        } else if (leader_set_type[set] == 1) { // BIP leader
            if (PSEL > 0) PSEL--;
        }
    }
}

//---------------------------------------------
// Print end-of-simulation statistics
void PrintStats() {
    int protected_blocks = 0, distant_blocks = 0, dead_blocks = 0, streaming_sets = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (rrpv[set][way] == 0) protected_blocks++;
            if (rrpv[set][way] == 3) distant_blocks++;
            if (dead_ctr[set][way] == 0) dead_blocks++;
        }
        if (stream_ctr[set] == 3) streaming_sets++;
    }
    int live_sigs = 0;
    for (uint32_t i = 0; i < SIG_TABLE_SIZE; ++i)
        if (sig_table[i] >= 2) live_sigs++;
    std::cout << "Adaptive LIP-BIP + Streaming Bypass + Signature-Driven Dead Block Policy" << std::endl;
    std::cout << "Protected blocks: " << protected_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "Distant blocks: " << distant_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "Dead blocks: " << dead_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "Streaming sets: " << streaming_sets << "/" << LLC_SETS << std::endl;
    std::cout << "Live signatures: " << live_sigs << "/" << SIG_TABLE_SIZE << std::endl;
    std::cout << "PSEL: " << PSEL << "/" << PSEL_MAX << std::endl;
}

//---------------------------------------------
// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    int protected_blocks = 0, distant_blocks = 0, dead_blocks = 0, streaming_sets = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (rrpv[set][way] == 0) protected_blocks++;
            if (rrpv[set][way] == 3) distant_blocks++;
            if (dead_ctr[set][way] == 0) dead_blocks++;
        }
        if (stream_ctr[set] == 3) streaming_sets++;
    }
    int live_sigs = 0;
    for (uint32_t i = 0; i < SIG_TABLE_SIZE; ++i)
        if (sig_table[i] >= 2) live_sigs++;
    std::cout << "Protected blocks (heartbeat): " << protected_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "Distant blocks (heartbeat): " << distant_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "Dead blocks (heartbeat): " << dead_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "Streaming sets (heartbeat): " << streaming_sets << "/" << LLC_SETS << std::endl;
    std::cout << "Live signatures (heartbeat): " << live_sigs << "/" << SIG_TABLE_SIZE << std::endl;
    std::cout << "PSEL (heartbeat): " << PSEL << "/" << PSEL_MAX << std::endl;
}