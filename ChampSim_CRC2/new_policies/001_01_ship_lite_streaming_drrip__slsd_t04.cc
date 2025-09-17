#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- Metadata structures ---
struct SLSD_BlockMeta {
    uint8_t rrpv;         // 2 bits: RRIP value
    uint8_t pc_sig;       // 6 bits: PC signature
};

SLSD_BlockMeta block_meta[LLC_SETS][LLC_WAYS];

// SHiP-lite outcome table: 2048 entries, 2 bits each
uint8_t ship_table[2048];

// DRRIP set-dueling: 32 leader sets for SRRIP, 32 for BRRIP, 10-bit PSEL
const uint32_t NUM_LEADER_SETS = 64;
const uint32_t SRRIP_LEADER_SETS = 32;
const uint32_t BRRIP_LEADER_SETS = 32;
uint32_t leader_sets[NUM_LEADER_SETS]; // set indices
uint16_t psel = 512;                   // 10 bits

// Streaming detector: 3 bits per set
struct SLSD_StreamSet {
    uint64_t last_addr;
    uint8_t stride_count;   // up to 3
    uint8_t streaming;      // 1 if streaming detected, else 0
    uint8_t window;         // streaming window countdown
};
SLSD_StreamSet stream_sets[LLC_SETS];

// --- Helper: get 6-bit PC signature ---
inline uint8_t get_pc_sig(uint64_t PC) {
    // Use bits [6:11] of PC
    return (PC >> 6) & 0x3F;
}

// --- Helper: get index into ship_table ---
inline uint16_t get_sig_idx(uint8_t sig) {
    return sig;
}

// RRIP constants
const uint8_t RRIP_MAX = 3;
const uint8_t RRIP_MRU = 0;
const uint8_t RRIP_DISTANT = 2;

// Streaming window length
const uint8_t STREAM_WIN = 8;

// --- Set-dueling leader set assignment ---
void assign_leader_sets() {
    // Assign first 32 sets as SRRIP leaders, next 32 as BRRIP leaders
    for (uint32_t i = 0; i < SRRIP_LEADER_SETS; ++i)
        leader_sets[i] = i;
    for (uint32_t i = 0; i < BRRIP_LEADER_SETS; ++i)
        leader_sets[SRRIP_LEADER_SETS + i] = LLC_SETS - 1 - i;
}

// --- Initialize replacement state ---
void InitReplacementState() {
    memset(block_meta, 0, sizeof(block_meta));
    memset(ship_table, 1, sizeof(ship_table)); // weakly reusable
    memset(stream_sets, 0, sizeof(stream_sets));
    assign_leader_sets();
    psel = 512;
}

// --- Find victim in the set ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Streaming bypass: if set is streaming, bypass (return LRU)
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
    // --- Streaming detector ---
    SLSD_StreamSet &ss = stream_sets[set];
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
        // Strengthen signature outcome
        if (ship_table[sig_idx] < 3)
            ship_table[sig_idx]++;
    }
    // --- On miss (new insertion) ---
    else {
        // Weaken signature outcome if block was dead
        if (ship_table[sig_idx] > 0)
            ship_table[sig_idx]--;

        // Insert new block
        block_meta[set][way].pc_sig = pc_sig;

        // Streaming: bypass (insert as LRU)
        if (ss.streaming && ss.window > 0) {
            block_meta[set][way].rrpv = RRIP_MAX;
        } else {
            // --- DRRIP set-dueling: select insertion depth ---
            bool is_srrip_leader = false, is_brrip_leader = false;
            for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i) {
                if (leader_sets[i] == set) {
                    if (i < SRRIP_LEADER_SETS) is_srrip_leader = true;
                    else is_brrip_leader = true;
                    break;
                }
            }

            uint8_t ins_rrpv;
            if (is_srrip_leader)
                ins_rrpv = RRIP_DISTANT; // SRRIP: insert at 2
            else if (is_brrip_leader)
                ins_rrpv = RRIP_MAX;      // BRRIP: insert at 3
            else
                ins_rrpv = (psel >= 512) ? RRIP_DISTANT : RRIP_MAX; // follower sets

            // SHiP-lite: bias insertion depth by signature outcome
            if (ship_table[sig_idx] >= 2)
                block_meta[set][way].rrpv = RRIP_MRU;
            else
                block_meta[set][way].rrpv = ins_rrpv;
        }
    }

    // --- DRRIP PSEL update ---
    // Only update for leader sets
    bool is_srrip_leader = false, is_brrip_leader = false;
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i) {
        if (leader_sets[i] == set) {
            if (i < SRRIP_LEADER_SETS) is_srrip_leader = true;
            else is_brrip_leader = true;
            break;
        }
    }
    if (is_srrip_leader && !hit && psel < 1023) psel++;      // SRRIP miss: prefer BRRIP
    if (is_brrip_leader && !hit && psel > 0) psel--;         // BRRIP miss: prefer SRRIP

    // --- Periodic decay of ship_table (every 1024 accesses) ---
    static uint64_t access_counter = 0;
    access_counter++;
    if ((access_counter & 0x3FF) == 0) {
        for (uint32_t i = 0; i < 2048; ++i)
            if (ship_table[i] > 0)
                ship_table[i]--;
    }
}

// --- Print end-of-simulation statistics ---
void PrintStats() {
    uint64_t streaming_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (stream_sets[s].streaming)
            streaming_sets++;
    std::cout << "SLSD: Streaming sets at end: " << streaming_sets << std::endl;
    std::cout << "SLSD: Final PSEL value: " << psel << std::endl;
}

// --- Print periodic (heartbeat) statistics ---
void PrintStats_Heartbeat() {
    // Optionally print streaming window stats
}