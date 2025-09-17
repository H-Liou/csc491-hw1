#include <vector>
#include <cstdint>
#include <iostream>
#include <algorithm>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// DIP parameters
#define PSEL_BITS 10
#define PSEL_MAX ((1<<PSEL_BITS)-1)
#define NUM_LEADER_SETS 64
#define LEADER_SET_STRIDE (LLC_SETS/NUM_LEADER_SETS)
#define LIP_INSERT 3 // always insert at RRPV=3 (LRU)
#define BIP_INSERT_PROB 32 // 1/32 inserts at MRU, else LRU

// SHiP-lite parameters
#define SIG_BITS 6
#define SIG_ENTRIES (1<<SIG_BITS)
#define OUTCOME_BITS 2
#define OUTCOME_MAX ((1<<OUTCOME_BITS)-1)
#define SIG_MASK (SIG_ENTRIES-1)

// Per-line dead-block counter
#define DEAD_CNTR_BITS 2
#define DEAD_CNTR_MAX ((1<<DEAD_CNTR_BITS)-1)
#define DEAD_DECAY_PERIOD 4096 // lines between global decay

struct block_state_t {
    uint8_t rrpv;      // 2b
    uint8_t sig;       // 6b
    uint8_t dead_cntr; // 2b
};

std::vector<std::vector<block_state_t>> blocks(LLC_SETS, std::vector<block_state_t>(LLC_WAYS));

// SHiP-lite signature table: outcome counters
std::vector<uint8_t> sig_table(SIG_ENTRIES, 1); // 2b per entry

// DIP set-dueling state
std::vector<uint8_t> set_type(LLC_SETS, 0); // 0: follower, 1: LIP leader, 2: BIP leader
uint16_t PSEL = PSEL_MAX/2;

// Dead-block decay state
uint64_t global_access_cnt = 0;

// --- Utility: assign leader sets for DIP ---
void assign_leader_sets() {
    for (uint32_t i = 0; i < NUM_LEADER_SETS; i++) {
        uint32_t s1 = i * LEADER_SET_STRIDE;
        uint32_t s2 = i * LEADER_SET_STRIDE + LEADER_SET_STRIDE/2;
        if (s1 < LLC_SETS) set_type[s1] = 1;  // LIP leader
        if (s2 < LLC_SETS) set_type[s2] = 2;  // BIP leader
    }
}

// Utility: compute signature from PC (6 bits, simple hash)
inline uint8_t get_sig(uint64_t PC) {
    return (uint8_t)((PC ^ (PC>>6) ^ (PC>>12)) & SIG_MASK);
}

void InitReplacementState() {
    for(uint32_t s=0; s<LLC_SETS; s++) {
        for(uint32_t w=0; w<LLC_WAYS; w++)
            blocks[s][w] = {LIP_INSERT, 0, 0};
        set_type[s] = 0;
    }
    std::fill(sig_table.begin(), sig_table.end(), 1);
    assign_leader_sets();
    PSEL = PSEL_MAX/2;
    global_access_cnt = 0;
}

// Find victim: prioritize blocks with dead_cntr==DEAD_CNTR_MAX (likely dead)
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Decay dead counters globally every DEAD_DECAY_PERIOD accesses
    global_access_cnt++;
    if(global_access_cnt % DEAD_DECAY_PERIOD == 0) {
        for(uint32_t s=0; s<LLC_SETS; s++)
            for(uint32_t w=0; w<LLC_WAYS; w++)
                if(blocks[s][w].dead_cntr > 0)
                    blocks[s][w].dead_cntr--;
    }

    // First, try to find a block with dead_cntr max
    for(uint32_t w=0; w<LLC_WAYS; w++)
        if(blocks[set][w].dead_cntr == DEAD_CNTR_MAX)
            return w;
    // Next, standard RRIP victim selection
    for(uint32_t w=0; w<LLC_WAYS; w++)
        if(blocks[set][w].rrpv == LIP_INSERT)
            return w;
    // Increment all RRPVs, retry
    for(uint32_t w=0; w<LLC_WAYS; w++)
        if(blocks[set][w].rrpv < LIP_INSERT)
            blocks[set][w].rrpv++;
    for(uint32_t w=0; w<LLC_WAYS; w++)
        if(blocks[set][w].rrpv == LIP_INSERT)
            return w;
    // Fallback
    return 0;
}

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
    uint8_t sig = get_sig(PC);

    // On hit: reset RRPV, set dead counter to 0, mark signature as reused
    if(hit) {
        blocks[set][way].rrpv = 0;
        blocks[set][way].sig = sig;
        blocks[set][way].dead_cntr = 0;
        if(sig_table[sig] < OUTCOME_MAX)
            sig_table[sig]++;
        // Set-dueling: leaders update PSEL
        uint8_t stype = set_type[set];
        if(stype == 1 && PSEL < PSEL_MAX) PSEL++;
        else if(stype == 2 && PSEL > 0) PSEL--;
        return;
    }

    // On miss/fill: update previous block's SHiP outcome (dead if not reused)
    uint8_t victim_sig = blocks[set][way].sig;
    if(sig_table[victim_sig] > 0)
        sig_table[victim_sig]--;

    // Update dead-block counter for victim (not reused)
    if(blocks[set][way].dead_cntr < DEAD_CNTR_MAX)
        blocks[set][way].dead_cntr++;

    // DIP insertion policy
    uint8_t stype = set_type[set];
    uint8_t ins_rrpv = LIP_INSERT;
    if(stype == 1) {
        // LIP leader: always LRU
        ins_rrpv = LIP_INSERT;
    } else if(stype == 2) {
        // BIP leader: insert at MRU with low probability
        ins_rrpv = (rand()%BIP_INSERT_PROB == 0) ? 0 : LIP_INSERT;
    } else {
        // Follower: use PSEL
        if(PSEL >= PSEL_MAX/2)
            ins_rrpv = LIP_INSERT;
        else
            ins_rrpv = (rand()%BIP_INSERT_PROB == 0) ? 0 : LIP_INSERT;
    }
    // SHiP-lite: override insertion if signature is reused
    if(sig_table[sig] >= (OUTCOME_MAX/2)) {
        ins_rrpv = 0; // insert at MRU
    }
    // Insert block
    blocks[set][way].rrpv = ins_rrpv;
    blocks[set][way].sig = sig;
    blocks[set][way].dead_cntr = 0;
}

void PrintStats() {
    std::cout << "DSDC: Final PSEL value = " << PSEL << std::endl;
    // Dead-block counter summary
    int likely_dead = 0;
    for(uint32_t s=0; s<LLC_SETS; s++)
        for(uint32_t w=0; w<LLC_WAYS; w++)
            if(blocks[s][w].dead_cntr == DEAD_CNTR_MAX)
                likely_dead++;
    std::cout << "DSDC: Blocks predicted dead = " << likely_dead << std::endl;
    // Signature reuse histogram
    int reused = 0, dead = 0;
    for(auto c : sig_table) {
        if(c >= (OUTCOME_MAX/2)) reused++;
        else dead++;
    }
    std::cout << "DSDC: Reused sigs = " << reused << ", Dead sigs = " << dead << std::endl;
}

void PrintStats_Heartbeat() {
    // No periodic stats needed
}