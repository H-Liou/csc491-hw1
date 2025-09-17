#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// RRPV parameters
#define RRPV_BITS 2
#define RRPV_MAX ((1<<RRPV_BITS)-1)
#define SRRIP_INSERT 2
#define BRRIP_INSERT 3
#define BRRIP_BIAS 32 // 1/32 ins at SRRIP, rest at BRRIP

// SHiP-lite signature parameters
#define SHIP_SIG_BITS 6
#define SHIP_SIG_TABLE_SIZE 1024 // 1K entries
#define SHIP_CTR_BITS 2

// DRRIP set-dueling
#define PSEL_BITS 10
#define PSEL_MAX ((1<<PSEL_BITS)-1)
#define NUM_LEADER_SETS 64
#define LEADER_SET_STRIDE (LLC_SETS/NUM_LEADER_SETS)

// Per-block state: RRPV, signature
struct block_state_t {
    uint8_t rrpv;           // 2b
    uint16_t signature;     // 6b
};
std::vector<std::vector<block_state_t>> blocks(LLC_SETS, std::vector<block_state_t>(LLC_WAYS));

// SHiP reuse predictor table: 2b outcome per signature
std::vector<uint8_t> ship_table(SHIP_SIG_TABLE_SIZE, 1); // Start neutral

// DRRIP set-dueling state
std::vector<uint8_t> set_type(LLC_SETS, 0); // 0: follower, 1: SRRIP leader, 2: BRRIP leader
uint16_t PSEL = PSEL_MAX/2;

// Utility: assign leader sets
void assign_leader_sets() {
    for (uint32_t i = 0; i < NUM_LEADER_SETS; i++) {
        uint32_t s1 = i * LEADER_SET_STRIDE;
        uint32_t s2 = i * LEADER_SET_STRIDE + LEADER_SET_STRIDE/2;
        if (s1 < LLC_SETS) set_type[s1] = 1;  // SRRIP leader
        if (s2 < LLC_SETS) set_type[s2] = 2;  // BRRIP leader
    }
}

// Extract SHiP signature: lower 6 bits of PC CRC
inline uint16_t get_signature(uint64_t PC) {
    return champsim_crc2(0, PC) & ((1<<SHIP_SIG_BITS)-1);
}

void InitReplacementState() {
    for(uint32_t s=0; s<LLC_SETS; s++)
        for(uint32_t w=0; w<LLC_WAYS; w++)
            blocks[s][w] = {RRPV_MAX, 0}; // RRPV max, signature 0

    std::fill(ship_table.begin(), ship_table.end(), 1); // neutral reuse
    assign_leader_sets();
    PSEL = PSEL_MAX/2;
}

// Find victim: standard RRPV search
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Increment RRPV until a block is found
    while (true) {
        for (uint32_t w = 0; w < LLC_WAYS; w++)
            if (blocks[set][w].rrpv == RRPV_MAX)
                return w;
        // If none, increment all RRPVs
        for (uint32_t w = 0; w < LLC_WAYS; w++)
            if (blocks[set][w].rrpv < RRPV_MAX)
                blocks[set][w].rrpv++;
    }
}

// Update replacement state on access/fill
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
    // Compute signature
    uint16_t sig = get_signature(PC);
    uint32_t ship_idx = sig;

    uint8_t stype = set_type[set];
    // On hit: reset RRPV, update SHiP table positively
    if (hit) {
        blocks[set][way].rrpv = 0;
        blocks[set][way].signature = sig;
        if (ship_table[ship_idx] < ((1<<SHIP_CTR_BITS)-1))
            ship_table[ship_idx]++;
        // Set-dueling: leaders update PSEL
        if(stype == 1 && PSEL < PSEL_MAX) PSEL++;
        else if(stype == 2 && PSEL > 0) PSEL--;
    } else {
        // On replacement/fill: update SHiP table negatively for victim's signature
        uint16_t victim_sig = blocks[set][way].signature;
        uint32_t victim_idx = victim_sig;
        if (ship_table[victim_idx] > 0)
            ship_table[victim_idx]--;
        // Choose insertion depth
        uint8_t ins_rrpv = 0;
        // Use SHiP table prediction if seen before
        if (ship_table[ship_idx] >= 2) {
            ins_rrpv = 0; // likely reuse, insert MRU
        } else if (ship_table[ship_idx] == 1) {
            // Use DRRIP policy (leader sets or PSEL)
            if(stype == 1)
                ins_rrpv = SRRIP_INSERT;
            else if(stype == 2)
                ins_rrpv = (rand()%BRRIP_BIAS==0)?SRRIP_INSERT:BRRIP_INSERT;
            else
                ins_rrpv = (PSEL >= PSEL_MAX/2)?SRRIP_INSERT:
                            ((rand()%BRRIP_BIAS==0)?SRRIP_INSERT:BRRIP_INSERT);
        } else {
            ins_rrpv = RRPV_MAX; // predicted dead, insert distant
        }
        blocks[set][way].rrpv = ins_rrpv;
        blocks[set][way].signature = sig;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "SLDH: Final PSEL value = " << PSEL << std::endl;
    // Optionally print reuse-predicted entries
    int high_reuse=0, low_reuse=0;
    for (auto ctr : ship_table) {
        if (ctr >= 2) high_reuse++;
        if (ctr == 0) low_reuse++;
    }
    std::cout << "SLDH: SHiP signatures high reuse = " << high_reuse
              << ", dead = " << low_reuse << std::endl;
}

void PrintStats_Heartbeat() {
    // No periodic stats needed
}