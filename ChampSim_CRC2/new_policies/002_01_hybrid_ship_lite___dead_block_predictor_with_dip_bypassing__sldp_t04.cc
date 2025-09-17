#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// Per-block metadata: RRIP, PC signature, dead-block counter
struct SLDP_BlockMeta {
    uint8_t rrpv;       // 2 bits
    uint8_t pc_sig;     // 6 bits
    uint8_t dead_ctr;   // 2 bits
};
SLDP_BlockMeta block_meta[LLC_SETS][LLC_WAYS];

// SHiP-lite outcome table: 4096 entries, 2 bits each
uint8_t ship_table[4096];

// DIP PSEL (10 bits)
uint16_t psel = 512; // midpoint

// DIP leader sets: first 16 for LIP, next 16 for BIP
const uint32_t NUM_LEADER_SETS = 32;
const uint32_t LIP_LEADER_SETS = 16;
const uint32_t BIP_LEADER_SETS = 16;

// Streaming detector: 3 bits per set
struct SLDP_StreamSet {
    uint64_t last_addr;
    uint8_t stride_count; // up to 3
    uint8_t streaming;    // 1 if streaming detected
    uint8_t window;       // streaming window countdown
};
SLDP_StreamSet stream_sets[LLC_SETS];

// Helper: get 6-bit PC signature
inline uint8_t get_pc_sig(uint64_t PC) {
    return (PC >> 2) & 0x3F;
}
// Helper: get index into ship_table
inline uint16_t get_ship_idx(uint8_t sig) {
    return sig;
}

// RRIP constants
const uint8_t RRIP_MAX = 3;
const uint8_t RRIP_MRU = 0;
const uint8_t RRIP_DISTANT = 2;

// DIP constants
const uint8_t BIP_PROB = 31; // 1/32 for BIP long insertion

// Streaming window length
const uint8_t STREAM_WIN = 8;

// Dead-block decay: periodically reset all dead counters (every N calls)
const uint32_t DEAD_DECAY_PERIOD = 4096;
uint32_t dead_decay_tick = 0;

// Initialize replacement state
void InitReplacementState() {
    memset(block_meta, 0, sizeof(block_meta));
    memset(ship_table, 1, sizeof(ship_table)); // weakly reusable
    memset(stream_sets, 0, sizeof(stream_sets));
    psel = 512;
    dead_decay_tick = 0;
}

// Find victim in the set (prefer blocks with high dead_ctr)
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // --- Streaming bypass: if set is streaming, always insert at LRU (highest RRPV) ---
    if (stream_sets[set].streaming && stream_sets[set].window > 0) {
        uint32_t lru_way = 0;
        uint8_t max_rrpv = 0;
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (block_meta[set][way].rrpv >= max_rrpv) {
                max_rrpv = block_meta[set][way].rrpv;
                lru_way = way;
            }
        }
        return lru_way;
    }

    // Prefer blocks with dead_ctr == 3 (most dead)
    for (uint32_t way = 0; way < LLC_WAYS; ++way) {
        if (block_meta[set][way].dead_ctr == 3)
            return way;
    }

    // RRIP victim selection
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
    SLDP_StreamSet &ss = stream_sets[set];
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

    // --- Dead-block decay ---
    dead_decay_tick++;
    if (dead_decay_tick % DEAD_DECAY_PERIOD == 0) {
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            for (uint32_t w = 0; w < LLC_WAYS; ++w)
                if (block_meta[s][w].dead_ctr > 0)
                    block_meta[s][w].dead_ctr--;
    }

    // --- SHiP-lite signature ---
    uint8_t pc_sig = get_pc_sig(PC);
    uint16_t sig_idx = get_ship_idx(pc_sig);

    // --- On hit ---
    if (hit) {
        block_meta[set][way].rrpv = RRIP_MRU;
        // Strengthen SHiP outcome
        if (ship_table[sig_idx] < 3)
            ship_table[sig_idx]++;
        // On hit, block is not dead
        block_meta[set][way].dead_ctr = 0;
    }
    // --- On miss (new insertion) ---
    else {
        // Weaken SHiP outcome on miss/eviction
        if (ship_table[sig_idx] > 0)
            ship_table[sig_idx]--;

        // Insert new block
        block_meta[set][way].pc_sig = pc_sig;

        // Mark victim as dead (increment dead_ctr)
        if (block_meta[set][way].dead_ctr < 3)
            block_meta[set][way].dead_ctr++;

        // Streaming: bypass (insert as LRU)
        if (ss.streaming && ss.window > 0) {
            block_meta[set][way].rrpv = RRIP_MAX;
        } else {
            // DIP set-dueling: leader sets
            bool is_lip_leader = (set < LIP_LEADER_SETS);
            bool is_bip_leader = (set >= LIP_LEADER_SETS && set < NUM_LEADER_SETS);
            uint8_t insert_rrpv = RRIP_MRU;

            // SHiP-guided insertion
            if (ship_table[sig_idx] >= 2)
                insert_rrpv = RRIP_MRU;
            else
                insert_rrpv = RRIP_DISTANT;

            // DIP: override insertion for non-leader sets
            if (!is_lip_leader && !is_bip_leader) {
                bool use_lip = (psel >= 512);
                if (use_lip) {
                    insert_rrpv = RRIP_MAX; // LIP: insert at LRU
                } else {
                    // BIP: insert at MRU with low probability, else LRU
                    if ((rand() % BIP_PROB) == 0)
                        insert_rrpv = RRIP_MRU;
                    else
                        insert_rrpv = RRIP_MAX;
                }
            }

            block_meta[set][way].rrpv = insert_rrpv;

            // DIP: update PSEL for leader sets
            if (is_lip_leader && !hit && insert_rrpv == RRIP_MAX && psel < 1023)
                psel++;
            if (is_bip_leader && !hit && insert_rrpv == RRIP_MRU && psel > 0)
                psel--;
        }
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    // Streaming set count
    uint64_t streaming_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (stream_sets[s].streaming)
            streaming_sets++;
    std::cout << "SLDP: Streaming sets at end: " << streaming_sets << std::endl;
    std::cout << "SLDP: Final PSEL value: " << psel << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Optionally print streaming window stats
}