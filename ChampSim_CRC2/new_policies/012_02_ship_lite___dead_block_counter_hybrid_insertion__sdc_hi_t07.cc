#include <vector>
#include <cstdint>
#include <iostream>
#include <algorithm>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// RRIP parameters
#define RRPV_BITS 2
#define RRPV_MAX ((1<<RRPV_BITS)-1)
#define SRRIP_INSERT 0
#define BRRIP_INSERT (RRPV_MAX-1)

// SHiP-lite parameters
#define SHIP_SIG_BITS 6
#define SHIP_SIG_ENTRIES 2048
#define SHIP_SIG_MASK (SHIP_SIG_ENTRIES-1)
#define SHIP_COUNTER_BITS 2
#define SHIP_COUNTER_MAX ((1<<SHIP_COUNTER_BITS)-1)
#define SHIP_COUNTER_INIT 1

// Dead-block counter parameters (2 bits per block)
#define DBC_BITS 2
#define DBC_MAX ((1<<DBC_BITS)-1)
#define DBC_DECAY_PERIOD 4096 // Decay all DBCs every this many updates

struct block_state_t {
    uint8_t rrpv;       // 2 bits: RRIP value
    uint16_t signature; // 6 bits: PC signature
    uint8_t dbc;        // 2 bits: dead-block counter
};

std::vector<std::vector<block_state_t>> blocks(LLC_SETS, std::vector<block_state_t>(LLC_WAYS));

// SHiP-lite table: 2048 entries, 2 bits each
std::vector<uint8_t> ship_table(SHIP_SIG_ENTRIES, SHIP_COUNTER_INIT);

uint64_t update_counter = 0;

// Utility: get SHiP signature from PC
inline uint16_t get_signature(uint64_t PC) {
    return (PC ^ (PC >> 2) ^ (PC >> 5)) & SHIP_SIG_MASK;
}

// Initialize replacement state
void InitReplacementState() {
    for(uint32_t s=0; s<LLC_SETS; s++) {
        for(uint32_t w=0; w<LLC_WAYS; w++) {
            blocks[s][w] = {RRPV_MAX, 0, 0}; // LRU, no signature, DBC=0
        }
    }
    std::fill(ship_table.begin(), ship_table.end(), SHIP_COUNTER_INIT);
    update_counter = 0;
}

// Find victim in the set (standard RRIP)
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    while (true) {
        for (uint32_t w = 0; w < LLC_WAYS; w++)
            if (blocks[set][w].rrpv == RRPV_MAX)
                return w;
        for (uint32_t w = 0; w < LLC_WAYS; w++)
            if (blocks[set][w].rrpv < RRPV_MAX)
                blocks[set][w].rrpv++;
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
    uint16_t sig = get_signature(PC);

    // Periodically decay all DBCs (approximate deadness over time)
    if(++update_counter % DBC_DECAY_PERIOD == 0) {
        for(uint32_t s=0; s<LLC_SETS; s++)
            for(uint32_t w=0; w<LLC_WAYS; w++)
                if(blocks[s][w].dbc > 0)
                    blocks[s][w].dbc--;
    }

    if (hit) {
        // On hit: set block to MRU, increment SHiP counter, reset DBC
        blocks[set][way].rrpv = SRRIP_INSERT;
        blocks[set][way].signature = sig;
        blocks[set][way].dbc = 0;
        if (ship_table[sig] < SHIP_COUNTER_MAX)
            ship_table[sig]++;
        return;
    }

    // On fill/replace: SHiP outcome update for victim block, increment DBC of victim
    uint16_t victim_sig = blocks[set][way].signature;
    if (ship_table[victim_sig] > 0)
        ship_table[victim_sig]--;
    if (blocks[set][way].dbc < DBC_MAX)
        blocks[set][way].dbc++;

    // Decide insertion RRPV: combine SHiP and DBC
    uint8_t ins_rrpv;
    if (blocks[set][way].dbc >= DBC_MAX) {
        // Block was frequently dead: insert at distant RRPV
        ins_rrpv = BRRIP_INSERT;
    } else if (ship_table[sig] >= (SHIP_COUNTER_MAX/2)) {
        // SHiP says likely reused: insert at MRU
        ins_rrpv = SRRIP_INSERT;
    } else {
        // Otherwise, insert at distant RRPV
        ins_rrpv = BRRIP_INSERT;
    }
    blocks[set][way].rrpv = ins_rrpv;
    blocks[set][way].signature = sig;
    blocks[set][way].dbc = 0;
}

// Print end-of-simulation statistics
void PrintStats() {
    int ship_high = 0, ship_low = 0;
    for(size_t i=0; i<ship_table.size(); i++) {
        if(ship_table[i] >= (SHIP_COUNTER_MAX/2))
            ship_high++;
        else
            ship_low++;
    }
    int dbc_dead = 0, dbc_alive = 0;
    for(uint32_t s=0; s<LLC_SETS; s++)
        for(uint32_t w=0; w<LLC_WAYS; w++)
            if(blocks[s][w].dbc >= DBC_MAX)
                dbc_dead++;
            else
                dbc_alive++;
    std::cout << "SDC-HI: SHiP high=" << ship_high << " low=" << ship_low << std::endl;
    std::cout << "SDC-HI: DBC dead=" << dbc_dead << " alive=" << dbc_alive << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // No periodic stats needed
}