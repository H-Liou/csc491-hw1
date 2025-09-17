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

// DRRIP set-dueling
#define PSEL_BITS 10
#define PSEL_MAX ((1<<PSEL_BITS)-1)
#define NUM_LEADER_SETS 32
#define LEADER_SET_STRIDE (LLC_SETS/NUM_LEADER_SETS)

// SHiP-lite parameters
#define SHIP_SIG_BITS 6
#define SHIP_SIG_ENTRIES 2048
#define SHIP_SIG_MASK (SHIP_SIG_ENTRIES-1)
#define SHIP_COUNTER_BITS 2
#define SHIP_COUNTER_MAX ((1<<SHIP_COUNTER_BITS)-1)
#define SHIP_COUNTER_INIT 1

// Dead-block counter parameters
#define DEAD_COUNTER_BITS 2
#define DEAD_COUNTER_MAX ((1<<DEAD_COUNTER_BITS)-1)
#define DEAD_COUNTER_INIT 0
#define DEAD_DECAY_PERIOD 1000000 // Decay every 1M accesses

struct block_state_t {
    uint8_t rrpv;      // 2 bits: RRIP value
    uint16_t signature;// 6 bits: PC signature
    uint8_t dead_ctr;  // 2 bits: dead-block approximation
};

std::vector<std::vector<block_state_t>> blocks(LLC_SETS, std::vector<block_state_t>(LLC_WAYS));

// SHiP-lite table: 2048 entries, 2 bits each
std::vector<uint8_t> ship_table(SHIP_SIG_ENTRIES, SHIP_COUNTER_INIT);

// DRRIP set-dueling
std::vector<uint8_t> is_srrip_leader(LLC_SETS, 0);
std::vector<uint8_t> is_brrip_leader(LLC_SETS, 0);
uint16_t psel = PSEL_MAX/2;

// Dead-block decay
uint64_t global_access_counter = 0;

void assign_leader_sets() {
    for(uint32_t i=0; i<NUM_LEADER_SETS; i++) {
        uint32_t srrip_set = i * LEADER_SET_STRIDE;
        uint32_t brrip_set = srrip_set + LEADER_SET_STRIDE/2;
        if(srrip_set < LLC_SETS)
            is_srrip_leader[srrip_set] = 1;
        if(brrip_set < LLC_SETS)
            is_brrip_leader[brrip_set] = 1;
    }
}

// Utility: get SHiP signature from PC
inline uint16_t get_signature(uint64_t PC) {
    return (PC ^ (PC >> 2) ^ (PC >> 5)) & SHIP_SIG_MASK;
}

// Initialize replacement state
void InitReplacementState() {
    for(uint32_t s=0; s<LLC_SETS; s++) {
        for(uint32_t w=0; w<LLC_WAYS; w++) {
            blocks[s][w] = {RRPV_MAX, 0, DEAD_COUNTER_INIT};
        }
    }
    std::fill(ship_table.begin(), ship_table.end(), SHIP_COUNTER_INIT);
    assign_leader_sets();
    psel = PSEL_MAX/2;
    global_access_counter = 0;
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
    // Prefer blocks with high dead-block counter and RRPV_MAX
    while(true) {
        // First, try to find block with RRPV_MAX and dead_ctr==DEAD_COUNTER_MAX
        for(uint32_t w=0; w<LLC_WAYS; w++)
            if(blocks[set][w].rrpv == RRPV_MAX && blocks[set][w].dead_ctr == DEAD_COUNTER_MAX)
                return w;
        // Next, any block with RRPV_MAX
        for(uint32_t w=0; w<LLC_WAYS; w++)
            if(blocks[set][w].rrpv == RRPV_MAX)
                return w;
        // Else, increment all RRPVs
        for(uint32_t w=0; w<LLC_WAYS; w++)
            if(blocks[set][w].rrpv < RRPV_MAX)
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
    global_access_counter++;

    uint16_t sig = get_signature(PC);

    // On hit: set block to MRU, increment SHiP counter, increment dead-block counter
    if(hit) {
        blocks[set][way].rrpv = SRRIP_INSERT;
        blocks[set][way].signature = sig;
        // SHiP: increment outcome counter (max at SHIP_COUNTER_MAX)
        if(ship_table[sig] < SHIP_COUNTER_MAX)
            ship_table[sig]++;
        // Dead-block: increment (max at DEAD_COUNTER_MAX)
        if(blocks[set][way].dead_ctr < DEAD_COUNTER_MAX)
            blocks[set][way].dead_ctr++;
        // DRRIP set-dueling: update PSEL for leader sets
        if(is_srrip_leader[set] && psel < PSEL_MAX)
            psel++;
        if(is_brrip_leader[set] && psel > 0)
            psel--;
        return;
    }

    // On fill/replace: SHiP outcome update for victim block
    uint16_t victim_sig = blocks[set][way].signature;
    if(ship_table[victim_sig] > 0)
        ship_table[victim_sig]--;

    // Dead-block: reset on fill
    blocks[set][way].dead_ctr = DEAD_COUNTER_INIT;

    // Decide insertion RRPV
    uint8_t ins_rrpv;
    if(is_srrip_leader[set]) {
        ins_rrpv = SRRIP_INSERT;
    } else if(is_brrip_leader[set]) {
        ins_rrpv = BRRIP_INSERT;
    } else {
        // SHiP bias: if signature counter high, insert at MRU; else at distant
        if(ship_table[sig] >= (SHIP_COUNTER_MAX/2))
            ins_rrpv = SRRIP_INSERT;
        else
            ins_rrpv = BRRIP_INSERT;
    }

    blocks[set][way].rrpv = ins_rrpv;
    blocks[set][way].signature = sig;

    // Periodic dead-block decay
    if(global_access_counter % DEAD_DECAY_PERIOD == 0) {
        for(uint32_t s=0; s<LLC_SETS; s++)
            for(uint32_t w=0; w<LLC_WAYS; w++)
                if(blocks[s][w].dead_ctr > 0)
                    blocks[s][w].dead_ctr--;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    int ship_high = 0, ship_low = 0;
    int dead_high = 0, dead_low = 0;
    for(size_t i=0; i<ship_table.size(); i++) {
        if(ship_table[i] >= (SHIP_COUNTER_MAX/2))
            ship_high++;
        else
            ship_low++;
    }
    for(uint32_t s=0; s<LLC_SETS; s++)
        for(uint32_t w=0; w<LLC_WAYS; w++)
            if(blocks[s][w].dead_ctr >= (DEAD_COUNTER_MAX/2))
                dead_high++;
            else
                dead_low++;
    std::cout << "SHiP-Lite+DeadBlock: SHiP high=" << ship_high << " low=" << ship_low << std::endl;
    std::cout << "SHiP-Lite+DeadBlock: Dead high=" << dead_high << " low=" << dead_low << std::endl;
    std::cout << "SHiP-Lite+DeadBlock: PSEL=" << psel << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // No periodic stats needed
}