#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- RRIP metadata ---
uint8_t rrpv[LLC_SETS][LLC_WAYS]; // 2 bits per block

// --- SHiP-lite metadata ---
#define SIG_BITS 6
#define SIG_MASK ((1 << SIG_BITS)-1)
uint8_t block_sig[LLC_SETS][LLC_WAYS]; // 6 bits per block

struct SHIPEntry {
    uint8_t counter; // 2 bits: outcome (reuse or dead)
};
SHIPEntry SHIP_table[1 << SIG_BITS]; // 64 entries total

// --- DRRIP set-dueling ---
#define PSEL_BITS 10
uint16_t PSEL = (1 << (PSEL_BITS-1)); // 10-bit saturating counter
#define SD_SRRIP_LEADER_SETS 32
#define SD_BRRIP_LEADER_SETS 32

// --- Streaming detector ---
uint64_t last_addr[LLC_SETS];      // 48 bits per set (paddr)
uint8_t stream_score[LLC_SETS];    // 2 bits per set

// --- Other bookkeeping ---
uint64_t access_counter = 0;
#define DECAY_PERIOD 100000

void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv));
    memset(block_sig, 0, sizeof(block_sig));
    for (int i = 0; i < (1 << SIG_BITS); ++i)
        SHIP_table[i].counter = 1; // weakly dead
    memset(last_addr, 0, sizeof(last_addr));
    memset(stream_score, 0, sizeof(stream_score));
    PSEL = (1 << (PSEL_BITS-1));
    access_counter = 0;
}

// Helper: get set type for set-dueling
enum SetType { NORMAL, SRRIP_LEADER, BRRIP_LEADER };
SetType get_set_type(uint32_t set) {
    if (set < SD_SRRIP_LEADER_SETS) return SRRIP_LEADER;
    if (set >= LLC_SETS - SD_BRRIP_LEADER_SETS) return BRRIP_LEADER;
    return NORMAL;
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
    // Prefer invalid block
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (!current_set[way].valid)
            return way;

    // RRIP: select block with max RRPV (3)
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            rrpv[set][way]++;
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
    access_counter++;

    // --- Streaming detector update ---
    uint64_t last = last_addr[set];
    uint8_t score = stream_score[set];
    if (last == 0) {
        last_addr[set] = paddr;
        stream_score[set] = 0;
    } else {
        uint64_t delta = (paddr > last) ? (paddr - last) : (last - paddr);
        if (delta == 64 || delta == 128) { // 1-2 block stride
            if (score < 3) stream_score[set]++;
        } else {
            if (score > 0) stream_score[set]--;
        }
        last_addr[set] = paddr;
    }
    bool streaming = (stream_score[set] >= 2);

    // --- SHiP-lite: signature extraction ---
    uint8_t sig = (PC >> 2) & SIG_MASK;
    block_sig[set][way] = sig;

    // --- Update SHIP_table based on hit/miss ---
    if (hit) {
        if (SHIP_table[sig].counter < 3)
            SHIP_table[sig].counter++;
    } else {
        if (SHIP_table[sig].counter > 0)
            SHIP_table[sig].counter--;
    }

    // --- RRIP insertion policy ---
    SetType set_type = get_set_type(set);
    uint8_t ship_ctr = SHIP_table[sig].counter;

    // Streaming detected: bypass insertion (RRPV=3)
    if (streaming) {
        rrpv[set][way] = 3;
    } else {
        // Set-dueling for insertion depth
        bool use_brrip = false;
        if (set_type == SRRIP_LEADER)
            use_brrip = false;
        else if (set_type == BRRIP_LEADER)
            use_brrip = true;
        else
            use_brrip = (PSEL < (1 << (PSEL_BITS-1)));

        // SHiP-lite override: if signature is high-reuse, insert at MRU
        if (ship_ctr >= 2) {
            rrpv[set][way] = 0;
        } else {
            // DRRIP: BRRIP inserts at distant RRPV (2) with probability ~1/32, else 3
            if (use_brrip) {
                rrpv[set][way] = ((rand() % 32) == 0) ? 2 : 3;
            } else {
                rrpv[set][way] = 2;
            }
        }
    }

    // --- RRIP promotion on hit ---
    if (hit) {
        rrpv[set][way] = 0; // promote to MRU
    }

    // --- DRRIP PSEL update (leader sets only) ---
    if (set_type == SRRIP_LEADER && !hit && !streaming) {
        if (PSEL < ((1 << PSEL_BITS)-1)) PSEL++;
    } else if (set_type == BRRIP_LEADER && !hit && !streaming) {
        if (PSEL > 0) PSEL--;
    }

    // --- Periodic decay of SHIP_table ---
    if (access_counter % DECAY_PERIOD == 0) {
        for (int i = 0; i < (1 << SIG_BITS); ++i)
            if (SHIP_table[i].counter > 0)
                SHIP_table[i].counter--;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    int high_reuse_signatures = 0;
    for (int i = 0; i < (1 << SIG_BITS); ++i)
        if (SHIP_table[i].counter >= 2) high_reuse_signatures++;
    int streaming_sets = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        if (stream_score[set] >= 2) streaming_sets++;
    std::cout << "SLDSB Policy: SHiP-Lite DRRIP with Streaming Bypass" << std::endl;
    std::cout << "High-reuse signatures: " << high_reuse_signatures << "/" << (1 << SIG_BITS) << std::endl;
    std::cout << "Streaming sets (score>=2): " << streaming_sets << "/" << LLC_SETS << std::endl;
    std::cout << "PSEL: " << PSEL << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    int high_reuse_signatures = 0;
    for (int i = 0; i < (1 << SIG_BITS); ++i)
        if (SHIP_table[i].counter >= 2) high_reuse_signatures++;
    int streaming_sets = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        if (stream_score[set] >= 2) streaming_sets++;
    std::cout << "High-reuse signatures (heartbeat): " << high_reuse_signatures << "/" << (1 << SIG_BITS) << std::endl;
    std::cout << "Streaming sets (heartbeat): " << streaming_sets << "/" << LLC_SETS << std::endl;
    std::cout << "PSEL (heartbeat): " << PSEL << std::endl;
}