#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- DRRIP metadata ---
uint8_t rrpv[LLC_SETS][LLC_WAYS]; // 2 bits/block

// DRRIP set-dueling: 64 leader sets for SRRIP, 64 for BRRIP
#define NUM_LEADER_SETS 64
uint8_t is_srrip_leader[LLC_SETS];
uint8_t is_brrip_leader[LLC_SETS];

// DRRIP PSEL selector (10 bits)
uint16_t psel = 512; // 0..1023

// --- SHiP-lite metadata ---
uint8_t pc_sig[LLC_SETS][LLC_WAYS];    // 4 bits/block
uint8_t ship_table[16];                // 2 bits/entry (indexed by 4-bit PC signature)

// --- Streaming detector (adaptive bypass) ---
struct StreamSet {
    uint64_t last_addr;
    int8_t stride_count; // up to 3
    uint8_t streaming;   // 1 if streaming detected
    uint8_t window;      // streaming window countdown
};
StreamSet stream_sets[LLC_SETS]; // 3 bits/set

// RRIP constants
const uint8_t RRIP_MAX = 3;
const uint8_t RRIP_MRU = 0;
const uint8_t RRIP_DISTANT = 2;

// Streaming window length
const uint8_t STREAM_WIN = 8;

// Helper: hash PC to 4 bits
inline uint8_t pc_hash(uint64_t PC) {
    return (PC ^ (PC >> 4) ^ (PC >> 8)) & 0xF;
}

// Initialize replacement state
void InitReplacementState() {
    memset(rrpv, RRIP_MAX, sizeof(rrpv));
    memset(pc_sig, 0, sizeof(pc_sig));
    memset(ship_table, 1, sizeof(ship_table)); // weakly reused
    memset(stream_sets, 0, sizeof(stream_sets));
    memset(is_srrip_leader, 0, sizeof(is_srrip_leader));
    memset(is_brrip_leader, 0, sizeof(is_brrip_leader));
    // Assign leader sets
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i) {
        is_srrip_leader[i] = 1;
        is_brrip_leader[LLC_SETS - 1 - i] = 1;
    }
    psel = 512;
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
    // Streaming: if detected, always evict block with RRPV==RRIP_MAX
    if (stream_sets[set].streaming && stream_sets[set].window > 0) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == RRIP_MAX)
                return way;
        // Increment RRPV and retry
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] < RRIP_MAX)
                rrpv[set][way]++;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == RRIP_MAX)
                return way;
        return 0;
    }

    // Otherwise, standard RRIP victim selection
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (rrpv[set][way] == RRIP_MAX)
            return way;
    // Increment RRPV and retry
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (rrpv[set][way] < RRIP_MAX)
            rrpv[set][way]++;
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (rrpv[set][way] == RRIP_MAX)
            return way;
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
    // --- Streaming detector ---
    StreamSet &ss = stream_sets[set];
    uint64_t cur_addr = paddr >> 6; // cache line granularity
    int64_t stride = cur_addr - ss.last_addr;
    if (ss.last_addr != 0 && (stride == 1 || stride == -1)) {
        if (ss.stride_count < 3) ss.stride_count++;
        if (ss.stride_count == 3 && !ss.streaming) {
            ss.streaming = 1;
            ss.window = STREAM_WIN;
        }
    } else {
        ss.stride_count = 0;
        ss.streaming = 0;
        ss.window = 0;
    }
    ss.last_addr = cur_addr;
    if (ss.streaming && ss.window > 0)
        ss.window--;

    // --- SHiP-lite signature ---
    uint8_t sig = pc_hash(PC);

    // --- DRRIP insertion depth selection ---
    bool use_srrip = false;
    if (is_srrip_leader[set])
        use_srrip = true;
    else if (is_brrip_leader[set])
        use_srrip = false;
    else
        use_srrip = (psel >= 512);

    uint8_t ins_rrpv;
    if (ss.streaming && ss.window > 0) {
        // Streaming detected: bypass (do not cache new block)
        // Mark block as dead (RRIP_MAX) so it is immediately evicted if inserted
        ins_rrpv = RRIP_MAX;
    } else {
        // DRRIP: insertion depth
        if (use_srrip)
            ins_rrpv = RRIP_DISTANT; // SRRIP: distant insertion
        else
            ins_rrpv = (rand() % 32 == 0) ? RRIP_DISTANT : RRIP_MAX; // BRRIP: mostly distant, rare MRU
        // SHiP overlay: if strong reuse PC, insert at MRU
        if (ship_table[sig] >= 2)
            ins_rrpv = RRIP_MRU;
    }

    if (hit) {
        rrpv[set][way] = RRIP_MRU;
        // SHiP table positive reinforcement
        if (ship_table[pc_sig[set][way]] < 3) ship_table[pc_sig[set][way]]++;
        // DRRIP PSEL update for leader sets
        if (is_srrip_leader[set] && psel < 1023) psel++;
        if (is_brrip_leader[set] && psel > 0) psel--;
    } else {
        // On insertion, set signature
        pc_sig[set][way] = sig;
        rrpv[set][way] = ins_rrpv;
        // SHiP table negative reinforcement (if block was dead on eviction)
        if (ship_table[sig] > 0 && ins_rrpv == RRIP_MAX)
            ship_table[sig]--;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    // Streaming set count
    uint64_t streaming_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (stream_sets[s].streaming)
            streaming_sets++;
    std::cout << "DS-ASB: Streaming sets at end: " << streaming_sets << std::endl;

    // SHiP table summary
    std::cout << "DS-ASB: SHiP table (reuse counters): ";
    for (int i = 0; i < 16; ++i)
        std::cout << (int)ship_table[i] << " ";
    std::cout << std::endl;

    // DRRIP PSEL value
    std::cout << "DS-ASB: DRRIP PSEL final value: " << psel << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Optionally print streaming set count or SHiP table summary
}