#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// RRIP parameters
#define RRPV_BITS 2
#define RRPV_MAX ((1<<RRPV_BITS)-1)

// DIP parameters
#define PSEL_BITS 10
#define PSEL_MAX ((1<<PSEL_BITS)-1)
#define NUM_LEADER_SETS 64
#define LEADER_SET_STRIDE (LLC_SETS/NUM_LEADER_SETS)

// SHiP-lite parameters
#define SIG_BITS 6
#define SIG_ENTRIES (1<<SIG_BITS)
#define OUTCOME_BITS 2
#define OUTCOME_MAX ((1<<OUTCOME_BITS)-1)
#define SIG_MASK (SIG_ENTRIES-1)

// Per-block state
struct block_state_t {
    uint8_t rrpv;      // 2b
    uint8_t sig;       // 6b
};

// SHiP-lite signature table: outcome counters
std::vector<uint8_t> sig_table(SIG_ENTRIES, 1); // 2b per entry, init to weakly reused

std::vector<std::vector<block_state_t>> blocks(LLC_SETS, std::vector<block_state_t>(LLC_WAYS));

// DIP set-dueling state
std::vector<uint8_t> set_type(LLC_SETS, 0); // 0: follower, 1: LIP leader, 2: BIP leader
uint16_t PSEL = PSEL_MAX/2;

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

void InitReplacementState() {
    for(uint32_t s=0; s<LLC_SETS; s++)
        for(uint32_t w=0; w<LLC_WAYS; w++)
            blocks[s][w] = {RRPV_MAX, 0}; // RRPV max, sig 0

    std::fill(sig_table.begin(), sig_table.end(), 1); // weakly reused

    for(uint32_t s=0; s<LLC_SETS; s++)
        set_type[s] = 0;
    assign_leader_sets();
    PSEL = PSEL_MAX/2;
}

// Victim selection: highest RRPV
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Find block with RRPV==RRPV_MAX (oldest)
    for(uint32_t w=0; w<LLC_WAYS; w++)
        if(blocks[set][w].rrpv == RRPV_MAX)
            return w;
    // If none, increment all RRPVs and retry
    for(uint32_t w=0; w<LLC_WAYS; w++)
        if(blocks[set][w].rrpv < RRPV_MAX)
            blocks[set][w].rrpv++;
    // Second pass
    for(uint32_t w=0; w<LLC_WAYS; w++)
        if(blocks[set][w].rrpv == RRPV_MAX)
            return w;
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

    // On hit: reset RRPV, mark signature as reused
    if(hit) {
        blocks[set][way].rrpv = 0;
        blocks[set][way].sig = sig;
        if(sig_table[sig] < OUTCOME_MAX)
            sig_table[sig]++;
        // Set-dueling: leaders update PSEL
        uint8_t stype = set_type[set];
        if(stype == 1 && PSEL < PSEL_MAX) PSEL++;
        else if(stype == 2 && PSEL > 0) PSEL--;
        return;
    }

    // On fill/replace: update previous block's outcome (dead if not reused)
    uint8_t victim_sig = blocks[set][way].sig;
    if(sig_table[victim_sig] > 0)
        sig_table[victim_sig]--;

    // DIP insertion policy
    uint8_t stype = set_type[set];
    uint8_t ins_rrpv = RRPV_MAX; // default: LIP (insert at distant)

    if(stype == 1) {
        // LIP leader: always insert at distant
        ins_rrpv = RRPV_MAX;
    } else if(stype == 2) {
        // BIP leader: insert at MRU with low probability
        ins_rrpv = (rand()%32==0) ? 0 : RRPV_MAX;
    } else {
        // Follower: use PSEL
        if(PSEL >= PSEL_MAX/2)
            ins_rrpv = RRPV_MAX; // LIP
        else
            ins_rrpv = (rand()%32==0) ? 0 : RRPV_MAX; // BIP
    }

    // SHiP-lite: override insertion if signature is reused
    if(sig_table[sig] >= (OUTCOME_MAX/2)) {
        ins_rrpv = 0; // insert at MRU
    }

    // Insert block
    blocks[set][way].rrpv = ins_rrpv;
    blocks[set][way].sig = sig;
}

void PrintStats() {
    std::cout << "SLDH: Final PSEL value = " << PSEL << std::endl;
    // Optional: print signature reuse histogram
    int reused = 0, dead = 0;
    for(auto c : sig_table) {
        if(c >= (OUTCOME_MAX/2)) reused++;
        else dead++;
    }
    std::cout << "SLDH: Reused sigs = " << reused << ", Dead sigs = " << dead << std::endl;
}

void PrintStats_Heartbeat() {
    // No periodic stats needed
}