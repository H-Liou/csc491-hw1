#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- SHiP-lite: 6-bit PC signatures per block, 2-bit outcome counter per signature
#define SIG_BITS 6
#define SIG_TABLE_ENTRIES 2048
uint8_t ship_counter[SIG_TABLE_ENTRIES]; // 2-bit outcome per signature

uint8_t block_signature[LLC_SETS][LLC_WAYS]; // 6-bit per block

// --- RRIP bits: 2 per block
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// --- Streaming detector: last addr/delta per set, flag
uint64_t last_addr[LLC_SETS];
int64_t last_delta[LLC_SETS];
uint8_t is_streaming[LLC_SETS];

// --- Set-dueling: 64 leader sets, 10-bit PSEL counter
#define LEADER_SETS 64
#define PSEL_BITS 10
uint16_t psel = (1 << (PSEL_BITS-1));
uint8_t is_leader_ship[LLC_SETS];
uint8_t is_leader_stream[LLC_SETS];

// --- Access counter for periodic stats
uint64_t access_count = 0;

// --- Utility: signature hash from PC
inline uint16_t get_signature(uint64_t PC) {
    // Mix PC bits, reduce to SIG_BITS
    return (champsim_crc2(PC, 0xABCD1234) ^ (PC >> 4)) & ((1 << SIG_BITS) - 1);
}

// Initialization
void InitReplacementState() {
    memset(ship_counter, 1, sizeof(ship_counter)); // neutral prediction
    memset(block_signature, 0, sizeof(block_signature));
    memset(rrpv, 3, sizeof(rrpv)); // distant
    memset(last_addr, 0, sizeof(last_addr));
    memset(last_delta, 0, sizeof(last_delta));
    memset(is_streaming, 0, sizeof(is_streaming));
    access_count = 0;

    // Assign leader sets
    memset(is_leader_ship, 0, sizeof(is_leader_ship));
    memset(is_leader_stream, 0, sizeof(is_leader_stream));
    for (uint32_t i = 0; i < LEADER_SETS; ++i) {
        is_leader_ship[i] = 1;
        is_leader_stream[LLC_SETS-1-i] = 1;
    }
    psel = (1 << (PSEL_BITS-1));
}

// Find victim (RRIP)
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] < 3) rrpv[set][way]++;
    }
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
    access_count++;

    // Streaming detector
    int64_t delta = (int64_t)paddr - (int64_t)last_addr[set];
    if (last_delta[set] != 0 && std::abs(delta) == std::abs(last_delta[set]) && (std::abs(delta) < 512*1024)) {
        is_streaming[set] = 1;
    } else {
        is_streaming[set] = 0;
    }
    last_delta[set] = delta;
    last_addr[set] = paddr;

    // Signature calculation
    uint16_t sig = get_signature(PC);

    // Hit update
    if (hit) {
        rrpv[set][way] = 0; // promote
        // On hit, increment outcome counter for block's signature
        uint8_t block_sig = block_signature[set][way];
        if (ship_counter[block_sig] < 3) ship_counter[block_sig]++;
    } else {
        // On miss, insert victim
        block_signature[set][way] = sig;

        // Choose policy: leader sets or PSEL
        bool use_ship = is_leader_ship[set] || (!is_leader_stream[set] && psel >= (1 << (PSEL_BITS-1)));
        bool use_stream = is_leader_stream[set] || (!is_leader_ship[set] && psel < (1 << (PSEL_BITS-1)));

        // If streaming detected and using streaming leader/stream policy, bypass or distant
        if (is_streaming[set] && use_stream) {
            rrpv[set][way] = 3; // insert distant (simulate bypass)
        } else if (use_ship) {
            // Insert depth based on signature outcome
            if (ship_counter[sig] == 3)
                rrpv[set][way] = 0; // frequent reuse: insert close
            else if (ship_counter[sig] == 2)
                rrpv[set][way] = 1; // moderate reuse
            else
                rrpv[set][way] = 3; // likely dead: insert distant
        } else {
            // Default: RRIP intermediate
            rrpv[set][way] = 2;
        }
    }

    // PSEL update: only in leader sets, reward/bias on hit
    if (is_leader_ship[set]) {
        if (hit && psel < ((1 << PSEL_BITS)-1)) psel++;
    }
    if (is_leader_stream[set]) {
        if (hit && psel > 0) psel--;
    }
}

// Print stats
void PrintStats() {
    std::cout << "SHiP-DSB: Final statistics." << std::endl;
    std::cout << "PSEL: " << psel << std::endl;
    uint32_t streaming_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (is_streaming[s]) streaming_sets++;
    std::cout << "Streaming sets at end: " << streaming_sets << " / " << LLC_SETS << std::endl;
    // Optionally show signature counter distribution
    uint32_t reuse_sig = 0, dead_sig = 0;
    for (uint32_t i = 0; i < SIG_TABLE_ENTRIES; ++i) {
        if (ship_counter[i] == 3) reuse_sig++;
        if (ship_counter[i] == 0) dead_sig++;
    }
    std::cout << "Signature reuse (cnt=3): " << reuse_sig << " / " << SIG_TABLE_ENTRIES << std::endl;
    std::cout << "Signature dead (cnt=0): " << dead_sig << " / " << SIG_TABLE_ENTRIES << std::endl;
}

void PrintStats_Heartbeat() {
    std::cout << "[Heartbeat] PSEL: " << psel << " Streaming sets: ";
    uint32_t streaming_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (is_streaming[s]) streaming_sets++;
    std::cout << streaming_sets << std::endl;
}