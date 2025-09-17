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

// LIP/BIP insertion
#define LIP_INSERT (LLC_WAYS-1) // Insert at LRU
#define BIP_PROB 32 // 1/32 probability to insert at LRU, else MRU

// SHiP-lite parameters
#define SIG_BITS 6
#define SIG_ENTRIES (1<<SIG_BITS)
#define OUTCOME_BITS 2
#define OUTCOME_MAX ((1<<OUTCOME_BITS)-1)
#define SIG_MASK (SIG_ENTRIES-1)

// Dead-block counter parameters
#define DEAD_BITS 2
#define DEAD_MAX ((1<<DEAD_BITS)-1)
#define DEAD_DECAY_INTERVAL 4096 // Decay every N fills

struct block_state_t {
    uint8_t lru;      // 4b: LRU stack position
    uint8_t sig;      // 6b: SHiP-lite signature
    uint8_t dead;     // 2b: dead-block counter
};

std::vector<std::vector<block_state_t>> blocks(LLC_SETS, std::vector<block_state_t>(LLC_WAYS));

// SHiP-lite signature table: outcome counters
std::vector<uint8_t> sig_table(SIG_ENTRIES, 1); // 2b per entry, init to weakly reused

// DIP set-dueling state
std::vector<uint8_t> set_type(LLC_SETS, 0); // 0: follower, 1: LIP leader, 2: BIP leader
uint16_t PSEL = PSEL_MAX/2;

// Dead-block decay state
uint64_t fill_count = 0;

// Utility: assign leader sets
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

// Initialize replacement state
void InitReplacementState() {
    for(uint32_t s=0; s<LLC_SETS; s++) {
        for(uint32_t w=0; w<LLC_WAYS; w++)
            blocks[s][w] = {w, 0, 0}; // LRU stack position, sig, dead
        set_type[s] = 0;
    }
    std::fill(sig_table.begin(), sig_table.end(), 1);
    assign_leader_sets();
    PSEL = PSEL_MAX/2;
    fill_count = 0;
}

// Find victim in the set (LRU, but bias against blocks with high dead count)
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Prefer blocks with highest dead counter, break ties by LRU
    uint32_t victim = 0;
    uint8_t max_dead = 0;
    uint8_t max_lru = 0;
    for(uint32_t w=0; w<LLC_WAYS; w++) {
        uint8_t d = blocks[set][w].dead;
        uint8_t l = blocks[set][w].lru;
        if(d > max_dead || (d == max_dead && l > max_lru)) {
            max_dead = d;
            max_lru = l;
            victim = w;
        }
    }
    return victim;
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
    uint8_t sig = get_sig(PC);

    // On hit: move to MRU, mark signature as reused
    if(hit) {
        // Move block to MRU (lru=0), increment others
        uint8_t old_lru = blocks[set][way].lru;
        for(uint32_t w=0; w<LLC_WAYS; w++)
            if(blocks[set][w].lru < old_lru)
                blocks[set][w].lru++;
        blocks[set][way].lru = 0;
        blocks[set][way].sig = sig;
        // SHiP-lite: mark signature as reused
        if(sig_table[sig] < OUTCOME_MAX)
            sig_table[sig]++;
        // DIP set-dueling: leaders update PSEL
        uint8_t stype = set_type[set];
        if(stype == 1 && PSEL < PSEL_MAX) PSEL++;
        else if(stype == 2 && PSEL > 0) PSEL--;
        return;
    }

    // On fill/replace: update previous block's outcome (dead if not reused)
    uint8_t victim_sig = blocks[set][way].sig;
    if(sig_table[victim_sig] > 0)
        sig_table[victim_sig]--;

    // Dead-block counter: increment on eviction
    if(blocks[set][way].dead < DEAD_MAX)
        blocks[set][way].dead++;

    // DIP insertion policy
    uint8_t stype = set_type[set];
    uint8_t ins_lru = 0; // default MRU
    if(stype == 1) {
        // LIP leader: insert at LRU
        ins_lru = LIP_INSERT;
    } else if(stype == 2) {
        // BIP leader: insert at LRU with low probability
        ins_lru = (rand()%BIP_PROB == 0) ? LIP_INSERT : 0;
    } else {
        // Follower: use PSEL
        if(PSEL >= PSEL_MAX/2)
            ins_lru = LIP_INSERT;
        else
            ins_lru = (rand()%BIP_PROB == 0) ? LIP_INSERT : 0;
    }

    // SHiP-lite: override insertion if signature is reused
    if(sig_table[sig] >= (OUTCOME_MAX/2)) {
        ins_lru = 0; // insert at MRU
    }

    // Dead-block counter: if block is frequently dead, bias to LRU
    if(blocks[set][way].dead >= DEAD_MAX) {
        ins_lru = LIP_INSERT;
    }

    // Insert block: update LRU stack
    uint8_t old_lru = blocks[set][way].lru;
    for(uint32_t w=0; w<LLC_WAYS; w++)
        if(blocks[set][w].lru < old_lru)
            blocks[set][w].lru++;
    blocks[set][way].lru = ins_lru;
    blocks[set][way].sig = sig;
    blocks[set][way].dead = 0; // reset dead counter on fill

    // Periodic dead-block decay
    fill_count++;
    if(fill_count % DEAD_DECAY_INTERVAL == 0) {
        for(uint32_t s=0; s<LLC_SETS; s++)
            for(uint32_t w=0; w<LLC_WAYS; w++)
                if(blocks[s][w].dead > 0)
                    blocks[s][w].dead--;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "DSH-DBC: Final PSEL value = " << PSEL << std::endl;
    // Signature reuse histogram
    int reused = 0, dead = 0;
    for(auto c : sig_table) {
        if(c >= (OUTCOME_MAX/2)) reused++;
        else dead++;
    }
    std::cout << "DSH-DBC: Reused sigs = " << reused << ", Dead sigs = " << dead << std::endl;
    // Dead-block counter summary
    int dead_blocks = 0;
    for(uint32_t s=0; s<LLC_SETS; s++)
        for(uint32_t w=0; w<LLC_WAYS; w++)
            if(blocks[s][w].dead >= DEAD_MAX)
                dead_blocks++;
    std::cout << "DSH-DBC: Blocks at max dead count = " << dead_blocks << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // No periodic stats needed
}