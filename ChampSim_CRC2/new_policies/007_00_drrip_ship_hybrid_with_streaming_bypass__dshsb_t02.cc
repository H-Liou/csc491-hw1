#include <vector>
#include <cstdint>
#include <iostream>
#include <algorithm>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// DRRIP parameters
#define RRPV_BITS 2
#define RRPV_MAX ((1<<RRPV_BITS)-1)
#define SRRIP_INSERT (RRPV_MAX-1) // 2 for 2b
#define BRRIP_INSERT (RRPV_MAX)   // 3 for 2b
#define BRRIP_PROB 32             // 1/32 probability to insert at SRRIP, else BRRIP

// Set-dueling parameters
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

// Streaming detector parameters
#define STREAM_HIST_BITS 8
#define STREAM_DETECT_THRESH 6 // >=6 monotonic deltas in last 8 accesses triggers streaming
#define STREAM_BYPASS_WINDOW 128 // Bypass for next 128 fills after detection

struct block_state_t {
    uint8_t rrpv;    // 2b: RRPV
    uint8_t sig;     // 6b: SHiP-lite signature
};

std::vector<std::vector<block_state_t>> blocks(LLC_SETS, std::vector<block_state_t>(LLC_WAYS));

// SHiP-lite signature table: outcome counters
std::vector<uint8_t> sig_table(SIG_ENTRIES, 1); // 2b per entry, init to weakly reused

// DRRIP set-dueling state
std::vector<uint8_t> set_type(LLC_SETS, 0); // 0: follower, 1: SRRIP leader, 2: BRRIP leader
uint16_t PSEL = PSEL_MAX/2;

// Streaming detector state
struct stream_state_t {
    uint64_t last_addr;
    uint8_t delta_hist[STREAM_HIST_BITS]; // 8b: recent delta directions (+/-/0)
    uint8_t hist_ptr;
    uint8_t monotonic_cnt;
    uint16_t bypass_count; // remaining bypass fills
};
std::vector<stream_state_t> stream_state(LLC_SETS);

// Utility: assign leader sets
void assign_leader_sets() {
    for (uint32_t i = 0; i < NUM_LEADER_SETS; i++) {
        uint32_t s1 = i * LEADER_SET_STRIDE;
        uint32_t s2 = i * LEADER_SET_STRIDE + LEADER_SET_STRIDE/2;
        if (s1 < LLC_SETS) set_type[s1] = 1;  // SRRIP leader
        if (s2 < LLC_SETS) set_type[s2] = 2;  // BRRIP leader
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
            blocks[s][w] = {RRPV_MAX, 0}; // RRPV, sig
        set_type[s] = 0;
        stream_state[s].last_addr = 0;
        std::fill(stream_state[s].delta_hist, stream_state[s].delta_hist+STREAM_HIST_BITS, 0);
        stream_state[s].hist_ptr = 0;
        stream_state[s].monotonic_cnt = 0;
        stream_state[s].bypass_count = 0;
    }
    std::fill(sig_table.begin(), sig_table.end(), 1);
    assign_leader_sets();
    PSEL = PSEL_MAX/2;
}

// Find victim in the set (standard RRIP: pick highest RRPV, break ties by way index)
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Streaming bypass: if active, always pick LRU (highest RRPV)
    if(stream_state[set].bypass_count > 0) {
        uint32_t victim = 0;
        uint8_t max_rrpv = 0;
        for(uint32_t w=0; w<LLC_WAYS; w++) {
            if(blocks[set][w].rrpv >= max_rrpv) {
                max_rrpv = blocks[set][w].rrpv;
                victim = w;
            }
        }
        return victim;
    }

    // Standard RRIP victim selection
    while(true) {
        for(uint32_t w=0; w<LLC_WAYS; w++) {
            if(blocks[set][w].rrpv == RRPV_MAX)
                return w;
        }
        // Increment all RRPVs if no victim found
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
    uint8_t sig = get_sig(PC);

    // --- Streaming detector update ---
    uint64_t last_addr = stream_state[set].last_addr;
    int64_t delta = (int64_t)paddr - (int64_t)last_addr;
    uint8_t dir = (delta > 0) ? 1 : ((delta < 0) ? 2 : 0); // 1=+, 2=-, 0=0
    stream_state[set].delta_hist[stream_state[set].hist_ptr] = dir;
    stream_state[set].hist_ptr = (stream_state[set].hist_ptr+1) % STREAM_HIST_BITS;
    stream_state[set].last_addr = paddr;

    // Count monotonic accesses in history
    uint8_t mono = 0;
    for(uint8_t i=0; i<STREAM_HIST_BITS; i++) {
        if(stream_state[set].delta_hist[i] == 1 || stream_state[set].delta_hist[i] == 2)
            mono++;
    }
    stream_state[set].monotonic_cnt = mono;

    // If monotonic count exceeds threshold, activate bypass
    if(stream_state[set].monotonic_cnt >= STREAM_DETECT_THRESH && stream_state[set].bypass_count == 0) {
        stream_state[set].bypass_count = STREAM_BYPASS_WINDOW;
    }

    // --- SHiP-lite update ---
    if(hit) {
        // On hit: set RRPV to 0 (MRU)
        blocks[set][way].rrpv = 0;
        blocks[set][way].sig = sig;
        // Mark signature as reused
        if(sig_table[sig] < OUTCOME_MAX)
            sig_table[sig]++;
        // DRRIP set-dueling: leaders update PSEL
        uint8_t stype = set_type[set];
        if(stype == 1 && PSEL < PSEL_MAX) PSEL++;
        else if(stype == 2 && PSEL > 0) PSEL--;
        return;
    }

    // On fill/replace: update previous block's outcome (dead if not reused)
    uint8_t victim_sig = blocks[set][way].sig;
    if(sig_table[victim_sig] > 0)
        sig_table[victim_sig]--;

    // --- Streaming bypass logic ---
    if(stream_state[set].bypass_count > 0) {
        // Bypass: do not fill block, decrement bypass counter
        stream_state[set].bypass_count--;
        // Still update streaming detector state, but skip fill
        return;
    }

    // --- DRRIP insertion policy ---
    uint8_t stype = set_type[set];
    uint8_t ins_rrpv = SRRIP_INSERT; // default SRRIP
    if(stype == 1) {
        // SRRIP leader: insert at SRRIP
        ins_rrpv = SRRIP_INSERT;
    } else if(stype == 2) {
        // BRRIP leader: insert at BRRIP with low probability SRRIP
        ins_rrpv = (rand()%BRRIP_PROB == 0) ? SRRIP_INSERT : BRRIP_INSERT;
    } else {
        // Follower: use PSEL
        if(PSEL >= PSEL_MAX/2)
            ins_rrpv = SRRIP_INSERT;
        else
            ins_rrpv = (rand()%BRRIP_PROB == 0) ? SRRIP_INSERT : BRRIP_INSERT;
    }

    // SHiP-lite: override insertion if signature is reused
    if(sig_table[sig] >= (OUTCOME_MAX/2)) {
        ins_rrpv = 0; // insert at MRU
    }

    // Insert block: set RRPV and signature
    blocks[set][way].rrpv = ins_rrpv;
    blocks[set][way].sig = sig;
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "DSHSB: Final PSEL value = " << PSEL << std::endl;
    // Signature reuse histogram
    int reused = 0, dead = 0;
    for(auto c : sig_table) {
        if(c >= (OUTCOME_MAX/2)) reused++;
        else dead++;
    }
    std::cout << "DSHSB: Reused sigs = " << reused << ", Dead sigs = " << dead << std::endl;
    // Streaming detector summary
    int bypassed_sets = 0;
    for(uint32_t s=0; s<LLC_SETS; s++)
        if(stream_state[s].bypass_count > 0)
            bypassed_sets++;
    std::cout << "DSHSB: Sets with active bypass at end = " << bypassed_sets << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // No periodic stats needed
}