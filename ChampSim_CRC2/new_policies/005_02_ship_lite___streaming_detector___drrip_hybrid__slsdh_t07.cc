#include <vector>
#include <cstdint>
#include <iostream>
#include <algorithm>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// RRIP (DRRIP) parameters
#define RRPV_BITS 2
#define RRPV_MAX ((1<<RRPV_BITS)-1)
#define SRRIP_INSERT 1     // Insert at RRPV=1 for SRRIP
#define BRRIP_INSERT_PROB 32 // 1/32 probability for BRRIP to insert at RRPV=1, else RRPV=RRPV_MAX

// DRRIP set-dueling
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
#define STREAM_WIN_SIZE 8 // Track last 8 addresses per set
#define STREAM_DELTA_THRESH 6 // At least 6 monotonic deltas out of 7

struct block_state_t {
    uint8_t rrpv;      // 2b
    uint8_t sig;       // 6b
};

std::vector<std::vector<block_state_t>> blocks(LLC_SETS, std::vector<block_state_t>(LLC_WAYS));

// SHiP-lite signature table: outcome counters
std::vector<uint8_t> sig_table(SIG_ENTRIES, 1); // 2b per entry, init to weakly reused

// DRRIP set-dueling state
std::vector<uint8_t> set_type(LLC_SETS, 0); // 0: follower, 1: SRRIP leader, 2: BRRIP leader
uint16_t PSEL = PSEL_MAX/2;

// Streaming detector per set
struct stream_info_t {
    uint64_t addr_history[STREAM_WIN_SIZE];
    uint8_t   idx;
    uint8_t   is_streaming; // 0: normal, 1: streaming detected
};
std::vector<stream_info_t> stream_info(LLC_SETS);

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

// Streaming detector logic
void update_streaming(uint32_t set, uint64_t paddr) {
    auto& info = stream_info[set];
    info.addr_history[info.idx % STREAM_WIN_SIZE] = paddr;
    info.idx++;
    // Only act if enough history is filled
    if (info.idx >= STREAM_WIN_SIZE) {
        uint8_t monotonic = 0;
        for (uint8_t i = 1; i < STREAM_WIN_SIZE; i++) {
            int64_t delta = (int64_t)info.addr_history[i] - (int64_t)info.addr_history[i-1];
            if (std::abs(delta) > 0 &&
                (delta == info.addr_history[1] - info.addr_history[0])) // consistent stride
                monotonic++;
        }
        info.is_streaming = (monotonic >= STREAM_DELTA_THRESH) ? 1 : 0;
    }
}

void InitReplacementState() {
    for(uint32_t s=0; s<LLC_SETS; s++) {
        for(uint32_t w=0; w<LLC_WAYS; w++)
            blocks[s][w] = {RRPV_MAX, 0};
        set_type[s] = 0;
        stream_info[s] = {{0}, 0, 0};
    }
    std::fill(sig_table.begin(), sig_table.end(), 1);
    assign_leader_sets();
    PSEL = PSEL_MAX/2;
}

uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Streaming detector update
    update_streaming(set, paddr);
    // Find block with RRPV==RRPV_MAX (oldest)
    for(uint32_t w=0; w<LLC_WAYS; w++)
        if(blocks[set][w].rrpv == RRPV_MAX)
            return w;
    // If none, increment all RRPVs and retry
    for(uint32_t w=0; w<LLC_WAYS; w++)
        if(blocks[set][w].rrpv < RRPV_MAX)
            blocks[set][w].rrpv++;
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
    stream_info_t& sinfo = stream_info[set];

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

    // Streaming detection: if set is streaming, bypass or insert at distant
    uint8_t ins_rrpv = RRPV_MAX; // default: distant
    if(sinfo.is_streaming) {
        // Bypass: insert at RRPV_MAX, or optionally skip fill (but Champsim API always fills)
        blocks[set][way].rrpv = RRPV_MAX;
        blocks[set][way].sig = sig;
        return;
    }

    // DRRIP insertion policy
    uint8_t stype = set_type[set];
    if(stype == 1) {
        // SRRIP leader: insert at RRPV=1
        ins_rrpv = SRRIP_INSERT;
    } else if(stype == 2) {
        // BRRIP leader: insert at RRPV=1 with low probability
        ins_rrpv = (rand()%BRRIP_INSERT_PROB == 0) ? SRRIP_INSERT : RRPV_MAX;
    } else {
        // Follower: use PSEL
        if(PSEL >= PSEL_MAX/2)
            ins_rrpv = SRRIP_INSERT;
        else
            ins_rrpv = (rand()%BRRIP_INSERT_PROB == 0) ? SRRIP_INSERT : RRPV_MAX;
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
    std::cout << "SLSDH: Final PSEL value = " << PSEL << std::endl;
    // Streaming sets summary
    int streaming_sets = 0;
    for(auto& info : stream_info)
        if(info.is_streaming) streaming_sets++;
    std::cout << "SLSDH: Streaming sets detected = " << streaming_sets << std::endl;
    // Signature reuse histogram
    int reused = 0, dead = 0;
    for(auto c : sig_table) {
        if(c >= (OUTCOME_MAX/2)) reused++;
        else dead++;
    }
    std::cout << "SLSDH: Reused sigs = " << reused << ", Dead sigs = " << dead << std::endl;
}

void PrintStats_Heartbeat() {
    // No periodic stats needed
}