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
#define SRRIP_INSERT (RRPV_MAX-1) // 2 for 2-bit
#define BRRIP_INSERT (RRPV_MAX)   // 3 for 2-bit
#define BRRIP_PROB 32             // 1/32 probability for BRRIP long insertion

// Set-dueling
#define PSEL_BITS 10
#define PSEL_MAX ((1<<PSEL_BITS)-1)
#define NUM_LEADER_SETS 64
#define LEADER_SET_STRIDE (LLC_SETS/NUM_LEADER_SETS)

// SHiP-lite
#define SIG_BITS 6
#define SIG_ENTRIES (1<<SIG_BITS)
#define OUTCOME_BITS 2
#define OUTCOME_MAX ((1<<OUTCOME_BITS)-1)
#define SIG_MASK (SIG_ENTRIES-1)

// Streaming detector
#define STREAM_DELTA_BITS 4 // 4b per-set delta history
#define STREAM_WINDOW 8     // Number of accesses to consider streaming
#define STREAM_THRESH 6     // If >=6/8 accesses are monotonic, treat as streaming

struct block_state_t {
    uint8_t rrpv;   // 2b: RRIP value
    uint8_t sig;    // 6b: SHiP-lite signature
};

std::vector<std::vector<block_state_t>> blocks(LLC_SETS, std::vector<block_state_t>(LLC_WAYS));

// SHiP-lite signature table: outcome counters
std::vector<uint8_t> sig_table(SIG_ENTRIES, 1); // 2b per entry, init to weakly reused

// DRRIP set-dueling state
std::vector<uint8_t> set_type(LLC_SETS, 0); // 0: follower, 1: SRRIP leader, 2: BRRIP leader
uint16_t PSEL = PSEL_MAX/2;

// Streaming detector state
struct stream_hist_t {
    uint64_t last_addr;
    uint8_t deltas[STREAM_WINDOW];
    uint8_t idx;
    uint8_t count;
};
std::vector<stream_hist_t> stream_hist(LLC_SETS);

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

// Streaming detector update: returns true if streaming detected
bool update_streaming(uint32_t set, uint64_t paddr) {
    stream_hist_t &hist = stream_hist[set];
    uint64_t delta = (hist.count == 0) ? 0 : paddr - hist.last_addr;
    hist.last_addr = paddr;
    if(hist.count < STREAM_WINDOW) hist.count++;
    hist.deltas[hist.idx] = (delta != 0 && (delta < 256)) ? 1 : 0; // treat small nonzero deltas as streaming
    hist.idx = (hist.idx + 1) % STREAM_WINDOW;
    uint8_t stream_cnt = 0;
    for(uint8_t i=0; i<STREAM_WINDOW; i++)
        stream_cnt += hist.deltas[i];
    return (stream_cnt >= STREAM_THRESH);
}

// Initialize replacement state
void InitReplacementState() {
    for(uint32_t s=0; s<LLC_SETS; s++) {
        for(uint32_t w=0; w<LLC_WAYS; w++)
            blocks[s][w] = {RRPV_MAX, 0}; // rrpv=3, sig=0
        set_type[s] = 0;
        stream_hist[s] = {0, {0}, 0, 0};
    }
    std::fill(sig_table.begin(), sig_table.end(), 1);
    assign_leader_sets();
    PSEL = PSEL_MAX/2;
}

// Find victim in the set (standard RRIP: prefer blocks with RRPV==max)
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    while(true) {
        for(uint32_t w=0; w<LLC_WAYS; w++) {
            if(blocks[set][w].rrpv == RRPV_MAX)
                return w;
        }
        // Increment all RRPVs (aging)
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

    // Streaming detector: update and check
    bool is_streaming = update_streaming(set, paddr);

    // On hit: set RRPV to 0 (MRU), mark signature as reused
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

    // On fill/replace: update previous block's outcome
    uint8_t victim_sig = blocks[set][way].sig;
    if(sig_table[victim_sig] > 0)
        sig_table[victim_sig]--;

    // Streaming bypass: if streaming detected, do not fill (simulate bypass)
    if(is_streaming) {
        // Do not fill block, leave RRPV at max, do not update signature
        blocks[set][way].rrpv = RRPV_MAX;
        blocks[set][way].sig = 0;
        return;
    }

    // DRRIP insertion policy
    uint8_t stype = set_type[set];
    uint8_t ins_rrpv = SRRIP_INSERT; // default SRRIP
    if(stype == 1) {
        // SRRIP leader: insert at SRRIP_INSERT
        ins_rrpv = SRRIP_INSERT;
    } else if(stype == 2) {
        // BRRIP leader: insert at BRRIP_INSERT with low probability
        ins_rrpv = (rand()%BRRIP_PROB == 0) ? BRRIP_INSERT : SRRIP_INSERT;
    } else {
        // Follower: use PSEL
        if(PSEL >= PSEL_MAX/2)
            ins_rrpv = SRRIP_INSERT;
        else
            ins_rrpv = (rand()%BRRIP_PROB == 0) ? BRRIP_INSERT : SRRIP_INSERT;
    }

    // SHiP-lite: override insertion if signature is reused
    if(sig_table[sig] >= (OUTCOME_MAX/2)) {
        ins_rrpv = 0; // insert at MRU
    }

    // Insert block: update block state
    blocks[set][way].rrpv = ins_rrpv;
    blocks[set][way].sig = sig;
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "DSSB: Final PSEL value = " << PSEL << std::endl;
    // Signature reuse histogram
    int reused = 0, dead = 0;
    for(auto c : sig_table) {
        if(c >= (OUTCOME_MAX/2)) reused++;
        else dead++;
    }
    std::cout << "DSSB: Reused sigs = " << reused << ", Dead sigs = " << dead << std::endl;
    // Streaming sets summary
    int stream_sets = 0;
    for(uint32_t s=0; s<LLC_SETS; s++) {
        uint8_t stream_cnt = 0;
        for(uint8_t i=0; i<STREAM_WINDOW; i++)
            stream_cnt += stream_hist[s].deltas[i];
        if(stream_cnt >= STREAM_THRESH)
            stream_sets++;
    }
    std::cout << "DSSB: Sets with streaming detected = " << stream_sets << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // No periodic stats needed
}