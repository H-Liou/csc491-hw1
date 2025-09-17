#include <vector>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- DRRIP: 2-bit RRPV per block ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// --- SHiP-lite: 6-bit signature per block, 2-bit outcome counter per signature ---
#define SIG_BITS 6
#define SIG_TABLE_SIZE 64
uint8_t block_sig[LLC_SETS][LLC_WAYS];      // Per-block signature
uint8_t ship_ctr[SIG_TABLE_SIZE];           // 2-bit saturating counter per signature

// --- DRRIP set-dueling ---
#define NUM_LEADER_SETS 32
uint32_t leader_sets[NUM_LEADER_SETS];
uint16_t psel = 512; // 10-bit PSEL, 0=SRRIP, 1023=BRRIP

// --- Streaming detector: per-set recent address delta, 2-bit streaming counter ---
uint64_t last_addr[LLC_SETS];
int64_t last_delta[LLC_SETS];
uint8_t stream_ctr[LLC_SETS]; // 2-bit: 0=not streaming, 3=strong streaming

// Helper: initialize leader sets
void InitLeaderSets() {
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i)
        leader_sets[i] = (LLC_SETS / NUM_LEADER_SETS) * i;
}

// Initialize replacement state
void InitReplacementState() {
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            rrpv[set][way] = 2;
            block_sig[set][way] = 0;
        }
    for (int i = 0; i < SIG_TABLE_SIZE; ++i)
        ship_ctr[i] = 1;
    InitLeaderSets();
    psel = 512;
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        last_addr[set] = 0;
        last_delta[set] = 0;
        stream_ctr[set] = 0;
    }
}

// Find victim in the set (SRRIP)
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
            if (rrpv[set][way] < 3)
                ++rrpv[set][way];
    }
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
    // --- Signature extraction ---
    uint8_t sig = ((PC >> 2) ^ (set & 0x3F)) & ((1 << SIG_BITS) - 1);

    // --- Streaming detector ---
    int64_t delta = (last_addr[set] == 0) ? 0 : (int64_t)paddr - (int64_t)last_addr[set];
    if (last_addr[set] != 0 && delta == last_delta[set]) {
        if (stream_ctr[set] < 3) stream_ctr[set]++;
    } else {
        if (stream_ctr[set] > 0) stream_ctr[set]--;
    }
    last_addr[set] = paddr;
    last_delta[set] = delta;

    // --- DRRIP set-dueling: determine policy for this set ---
    bool is_leader_srrip = false, is_leader_brrip = false;
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i) {
        if (set == leader_sets[i]) {
            if (i < NUM_LEADER_SETS / 2) is_leader_srrip = true;
            else is_leader_brrip = true;
            break;
        }
    }
    bool use_brrip = false;
    if (is_leader_srrip) use_brrip = false;
    else if (is_leader_brrip) use_brrip = true;
    else use_brrip = (psel >= 512);

    // --- SHiP update ---
    if (hit) {
        // Block reused: reward signature, set to MRU
        if (ship_ctr[block_sig[set][way]] < 3)
            ship_ctr[block_sig[set][way]]++;
        rrpv[set][way] = 0;
    } else {
        // Block evicted: decay signature if not reused
        uint8_t old_sig = block_sig[set][way];
        if (ship_ctr[old_sig] > 0)
            ship_ctr[old_sig]--;

        // Insert new block: record signature
        block_sig[set][way] = sig;

        // --- Streaming bypass logic ---
        bool streaming = (stream_ctr[set] >= 2);

        // --- Insertion depth ---
        uint8_t ins_rrpv = 2; // default distant
        if (ship_ctr[sig] >= 2)
            ins_rrpv = 0; // hot signature: MRU
        else
            ins_rrpv = use_brrip ? 2 : 1; // BRRIP: mostly distant, SRRIP: intermediate

        if (streaming) {
            // If streaming, always insert at distant RRPV (2), or optionally bypass
            ins_rrpv = 2;
            // Optional: bypass if streaming is strong and set is full of distant blocks
            // (not implemented for simplicity)
        }
        rrpv[set][way] = ins_rrpv;

        // --- DRRIP set-dueling feedback ---
        if (is_leader_srrip && !hit && ship_ctr[sig] < 2 && !streaming) {
            // If SRRIP leader set misses on cold signature, increment PSEL (favor BRRIP)
            if (psel < 1023) psel++;
        }
        if (is_leader_brrip && hit && ship_ctr[sig] >= 2) {
            // If BRRIP leader set hits on hot signature, decrement PSEL (favor SRRIP)
            if (psel > 0) psel--;
        }
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    int hot_sigs = 0, cold_sigs = 0;
    for (int i = 0; i < SIG_TABLE_SIZE; ++i)
        if (ship_ctr[i] >= 2) hot_sigs++;
        else cold_sigs++;
    std::cout << "SHiP-DRRIP-SB: Hot signatures: " << hot_sigs
              << " / " << SIG_TABLE_SIZE << std::endl;
    std::cout << "SHiP-DRRIP-SB: Cold signatures: " << cold_sigs << std::endl;
    std::cout << "SHiP-DRRIP-SB: Final PSEL: " << psel << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    int streaming_sets = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        if (stream_ctr[set] >= 2) streaming_sets++;
    std::cout << "SHiP-DRRIP-SB: Streaming sets: " << streaming_sets << std::endl;
    std::cout << "SHiP-DRRIP-SB: PSEL: " << psel << std::endl;
}