#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// SHiP-lite: 6-bit PC signature per block, 2-bit outcome counter per signature (4096 entries)
struct SADRRIP_BlockMeta {
    uint8_t rrpv;         // 2 bits: RRIP value
    uint8_t pc_sig;       // 6 bits: PC signature
};

SADRRIP_BlockMeta block_meta[LLC_SETS][LLC_WAYS];

// SHiP outcome table: 4096 entries, 2 bits each
uint8_t ship_table[4096];

// Per-block outcome counter (2 bits/block)
uint8_t block_outcome[LLC_SETS][LLC_WAYS];

// DRRIP set-dueling: 64 leader sets, 10-bit PSEL
const uint32_t NUM_LEADER_SETS = 64;
const uint32_t PSEL_MAX = 1023;
uint16_t psel = PSEL_MAX / 2;
uint8_t is_leader_set[LLC_SETS]; // 0: normal, 1: SRRIP leader, 2: BRRIP leader

// Streaming detector: 3 bits/set
struct SADRRIP_StreamSet {
    uint64_t last_addr;
    uint8_t stride_count;   // up to 3
    uint8_t streaming;      // 1 if streaming detected, else 0
    uint8_t window;         // streaming window countdown
};
SADRRIP_StreamSet stream_sets[LLC_SETS];
const uint8_t STREAM_WIN = 8;

// RRIP constants
const uint8_t RRIP_MAX = 3;
const uint8_t RRIP_MRU = 0;
const uint8_t RRIP_DISTANT = 2;

// Helper: get 6-bit PC signature
inline uint8_t get_pc_sig(uint64_t PC) {
    return (PC >> 2) & 0x3F;
}

// Helper: get index into ship_table
inline uint16_t get_sig_idx(uint8_t sig) {
    return sig;
}

// Initialize replacement state
void InitReplacementState() {
    memset(block_meta, 0, sizeof(block_meta));
    memset(ship_table, 1, sizeof(ship_table)); // weakly reusable
    memset(block_outcome, 0, sizeof(block_outcome));
    memset(stream_sets, 0, sizeof(stream_sets));
    memset(is_leader_set, 0, sizeof(is_leader_set));
    // Assign leader sets for DRRIP set-dueling
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i) {
        is_leader_set[i] = 1; // SRRIP leader
        is_leader_set[LLC_SETS - 1 - i] = 2; // BRRIP leader
    }
    psel = PSEL_MAX / 2;
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
    // Streaming bypass: if set is streaming, insert at LRU (handled in Update)
    // Normal RRIP victim selection
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (block_meta[set][way].rrpv == RRIP_MAX)
                return way;
        }
        // Increment all RRPVs
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (block_meta[set][way].rrpv < RRIP_MAX)
                block_meta[set][way].rrpv++;
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
    // --- Streaming detector ---
    SADRRIP_StreamSet &ss = stream_sets[set];
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
    uint8_t pc_sig = get_pc_sig(PC);
    uint16_t sig_idx = get_sig_idx(pc_sig);

    // --- On hit ---
    if (hit) {
        block_meta[set][way].rrpv = RRIP_MRU;
        // Mark block as live
        if (block_outcome[set][way] < 3)
            block_outcome[set][way]++;
        // Strengthen signature outcome
        if (ship_table[sig_idx] < 3)
            ship_table[sig_idx]++;
    }
    // --- On miss (new insertion) ---
    else {
        // If block was not reused before eviction, weaken signature
        if (block_outcome[set][way] == 0 && ship_table[block_meta[set][way].pc_sig] > 0)
            ship_table[block_meta[set][way].pc_sig]--;
        // Insert new block
        block_meta[set][way].pc_sig = pc_sig;
        block_outcome[set][way] = 0;

        // Streaming: insert at LRU (RRPV=3)
        if (ss.streaming && ss.window > 0) {
            block_meta[set][way].rrpv = RRIP_MAX;
        } else {
            // DRRIP set-dueling: choose insertion policy
            uint8_t use_srrip = 0;
            if (is_leader_set[set] == 1) use_srrip = 1; // SRRIP leader
            else if (is_leader_set[set] == 2) use_srrip = 0; // BRRIP leader
            else use_srrip = (psel >= (PSEL_MAX / 2)); // normal sets

            // SHiP-lite: hot signature → MRU, else distant
            if (ship_table[sig_idx] >= 2)
                block_meta[set][way].rrpv = RRIP_MRU;
            else {
                if (use_srrip)
                    block_meta[set][way].rrpv = RRIP_DISTANT; // SRRIP: RRPV=2
                else
                    block_meta[set][way].rrpv = (rand() % 2) ? RRIP_DISTANT : RRIP_MAX; // BRRIP: mostly distant, sometimes LRU
            }
        }
    }

    // --- DRRIP PSEL update (leader sets only) ---
    if (!hit) {
        if (is_leader_set[set] == 1 && block_meta[set][way].rrpv == RRIP_MRU) {
            // SRRIP leader: insertion at MRU, increase PSEL
            if (psel < PSEL_MAX) psel++;
        }
        else if (is_leader_set[set] == 2 && block_meta[set][way].rrpv == RRIP_MRU) {
            // BRRIP leader: insertion at MRU, decrease PSEL
            if (psel > 0) psel--;
        }
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    // Optionally print streaming set stats, PSEL value, etc.
    uint64_t streaming_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (stream_sets[s].streaming)
            streaming_sets++;
    std::cout << "SADRRIP: Streaming sets at end: " << streaming_sets << std::endl;
    std::cout << "SADRRIP: Final PSEL value: " << psel << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Optionally print streaming window stats
}