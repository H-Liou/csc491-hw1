#include <vector>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// SHiP-lite: 4-bit PC signature per block, global table 32x2 bits
uint8_t pc_sig[LLC_SETS][LLC_WAYS]; // 4 bits/block
uint8_t ship_table[32]; // 2 bits/entry

// Streaming detector: per-set, last addr/delta, 1-bit flag, 3-bit confidence
uint64_t last_addr[LLC_SETS];
int64_t last_delta[LLC_SETS];
uint8_t streaming_flag[LLC_SETS]; // 1 bit/set
uint8_t stream_conf[LLC_SETS];    // 3 bits/set

// DIP set-dueling: 32 leader sets for LIP, 32 for BIP, 10-bit PSEL
const uint32_t NUM_LEADER_SETS = 64;
const uint32_t LEADER_SETS_LIP = 32;
const uint32_t LEADER_SETS_BIP = 32;
bool is_leader_set_lip[LLC_SETS];
bool is_leader_set_bip[LLC_SETS];
uint16_t PSEL = 512; // 10 bits, mid-value

// LRU stack: 4 bits per block (0=MRU, 15=LRU)
uint8_t lru_stack[LLC_SETS][LLC_WAYS];

// Helper: hash PC to 5 bits
inline uint8_t pc_hash(uint64_t PC) {
    return (PC ^ (PC >> 7) ^ (PC >> 13)) & 0x1F;
}

// Assign leader sets for DIP
void AssignLeaderSets() {
    memset(is_leader_set_lip, 0, sizeof(is_leader_set_lip));
    memset(is_leader_set_bip, 0, sizeof(is_leader_set_bip));
    for (uint32_t i = 0; i < LEADER_SETS_LIP; ++i)
        is_leader_set_lip[(i * LLC_SETS) / NUM_LEADER_SETS] = true;
    for (uint32_t i = 0; i < LEADER_SETS_BIP; ++i)
        is_leader_set_bip[(i * LLC_SETS) / NUM_LEADER_SETS + 1] = true;
}

// Initialize replacement state
void InitReplacementState() {
    memset(pc_sig, 0, sizeof(pc_sig));
    memset(ship_table, 1, sizeof(ship_table)); // weakly reused
    memset(last_addr, 0, sizeof(last_addr));
    memset(last_delta, 0, sizeof(last_delta));
    memset(streaming_flag, 0, sizeof(streaming_flag));
    memset(stream_conf, 0, sizeof(stream_conf));
    AssignLeaderSets();
    memset(lru_stack, 0, sizeof(lru_stack));
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            lru_stack[set][way] = way; // initialize stack: way 0 MRU, way 15 LRU
    PSEL = 512;
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
    // Streaming: bypass, pick LRU (do not insert)
    if (streaming_flag[set]) {
        // Find LRU block
        uint32_t lru_way = 0;
        uint8_t max_stack = 0;
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (lru_stack[set][way] > max_stack) {
                max_stack = lru_stack[set][way];
                lru_way = way;
            }
        }
        return lru_way;
    }

    // Otherwise, pick LRU block
    uint32_t lru_way = 0;
    uint8_t max_stack = 0;
    for (uint32_t way = 0; way < LLC_WAYS; ++way) {
        if (lru_stack[set][way] > max_stack) {
            max_stack = lru_stack[set][way];
            lru_way = way;
        }
    }
    return lru_way;
}

// Update LRU stack for set/way: move way to MRU, bump others
void UpdateLRU(uint32_t set, uint32_t way) {
    uint8_t prev = lru_stack[set][way];
    for (uint32_t w = 0; w < LLC_WAYS; ++w) {
        if (lru_stack[set][w] < prev)
            lru_stack[set][w]++;
    }
    lru_stack[set][way] = 0;
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
    // --- Streaming detector update ---
    int64_t delta = (int64_t)paddr - (int64_t)last_addr[set];
    if (last_addr[set] != 0 && delta == last_delta[set]) {
        if (stream_conf[set] < 7) stream_conf[set]++;
    } else {
        if (stream_conf[set] > 0) stream_conf[set]--;
    }
    last_addr[set] = paddr;
    last_delta[set] = delta;
    streaming_flag[set] = (stream_conf[set] >= 5) ? 1 : 0;

    // --- SHiP signature ---
    uint8_t sig = pc_hash(PC);

    // --- DIP set-dueling: choose LIP or BIP ---
    bool use_lip = false, use_bip = false;
    if (is_leader_set_lip[set]) use_lip = true;
    else if (is_leader_set_bip[set]) use_bip = true;
    else use_lip = (PSEL >= 512);

    // --- On cache hit ---
    if (hit) {
        UpdateLRU(set, way); // move to MRU
        pc_sig[set][way] = sig;
        if (ship_table[sig] < 3) ship_table[sig]++;
        // PSEL: hits in leader sets
        if (is_leader_set_lip[set] && PSEL < 1023) PSEL++;
        if (is_leader_set_bip[set] && PSEL > 0) PSEL--;
        return;
    }

    // --- On cache miss or fill ---
    // Streaming: bypass insertion (do not update metadata, just evict LRU)
    if (streaming_flag[set]) {
        // Decay SHiP counter for signature
        if (ship_table[sig] > 0) ship_table[sig]--;
        // PSEL: misses in leader sets
        if (is_leader_set_lip[set] && PSEL > 0) PSEL--;
        if (is_leader_set_bip[set] && PSEL < 1023) PSEL++;
        return;
    }

    // SHiP: if signature shows frequent reuse, insert at MRU
    bool insert_mru = (ship_table[sig] >= 2);

    // DIP: choose insertion depth
    uint32_t ins_way = way;
    if (insert_mru) {
        // Insert at MRU
        UpdateLRU(set, ins_way);
    } else if (use_lip) {
        // Insert at LRU
        uint8_t max_stack = 0;
        uint32_t lru_way = 0;
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            if (lru_stack[set][w] > max_stack) {
                max_stack = lru_stack[set][w];
                lru_way = w;
            }
        }
        UpdateLRU(set, lru_way);
        ins_way = lru_way;
    } else if (use_bip) {
        // Insert at MRU 1/32 fills, else at LRU
        static uint32_t bip_ctr = 0;
        if ((bip_ctr++ % 32) == 0)
            UpdateLRU(set, way); // MRU
        else {
            uint8_t max_stack = 0;
            uint32_t lru_way = 0;
            for (uint32_t w = 0; w < LLC_WAYS; ++w) {
                if (lru_stack[set][w] > max_stack) {
                    max_stack = lru_stack[set][w];
                    lru_way = w;
                }
            }
            UpdateLRU(set, lru_way);
            ins_way = lru_way;
        }
    } else {
        // Dynamic: use PSEL winner
        if (PSEL >= 512) {
            // LIP
            uint8_t max_stack = 0;
            uint32_t lru_way = 0;
            for (uint32_t w = 0; w < LLC_WAYS; ++w) {
                if (lru_stack[set][w] > max_stack) {
                    max_stack = lru_stack[set][w];
                    lru_way = w;
                }
            }
            UpdateLRU(set, lru_way);
            ins_way = lru_way;
        } else {
            // BIP
            static uint32_t bip_ctr2 = 0;
            if ((bip_ctr2++ % 32) == 0)
                UpdateLRU(set, way); // MRU
            else {
                uint8_t max_stack = 0;
                uint32_t lru_way = 0;
                for (uint32_t w = 0; w < LLC_WAYS; ++w) {
                    if (lru_stack[set][w] > max_stack) {
                        max_stack = lru_stack[set][w];
                        lru_way = w;
                    }
                }
                UpdateLRU(set, lru_way);
                ins_way = lru_way;
            }
        }
    }

    // Update block metadata
    pc_sig[set][ins_way] = sig;
    if (ship_table[sig] > 0) ship_table[sig]--; // decay on fill

    // PSEL: misses in leader sets
    if (is_leader_set_lip[set] && PSEL > 0) PSEL--;
    if (is_leader_set_bip[set] && PSEL < 1023) PSEL++;
}

// Print end-of-simulation statistics
void PrintStats() {
    // Streaming summary
    uint64_t streaming_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (streaming_flag[s])
            streaming_sets++;
    std::cout << "SL-SBDIP: Streaming sets at end: " << streaming_sets << " / " << LLC_SETS << std::endl;

    // SHiP table
    std::cout << "SL-SBDIP: SHiP table (reuse counters): ";
    for (int i = 0; i < 32; ++i)
        std::cout << (int)ship_table[i] << " ";
    std::cout << std::endl;

    // Print PSEL value
    std::cout << "SL-SBDIP: DIP PSEL = " << (int)PSEL << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // No periodic decay needed; SHiP counters decay on fills
}