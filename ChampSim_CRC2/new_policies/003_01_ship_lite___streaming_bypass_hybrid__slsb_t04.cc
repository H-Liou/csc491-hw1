#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// SHiP-lite parameters
#define SIG_BITS 6
#define SIG_ENTRIES (1 << SIG_BITS)
#define OUTCOME_BITS 2
#define OUTCOME_MAX ((1 << OUTCOME_BITS) - 1)
#define OUTCOME_MIN 0

// RRIP parameters
#define RRPV_BITS 2
#define RRPV_MAX ((1 << RRPV_BITS) - 1)
#define RRPV_MRU 0
#define RRPV_LRU RRPV_MAX

// Streaming detector
#define STREAM_HIST_LEN 4
#define STREAM_DELTA_THR 3

struct block_state_t {
    uint8_t rrpv;                  // 2b
    uint8_t outcome;               // 2b (for SHiP)
    uint8_t sig;                   // 6b (hashed PC signature)
};

std::vector<std::vector<block_state_t>> blocks(LLC_SETS, std::vector<block_state_t>(LLC_WAYS));

// SHiP-lite global table: outcome counter per signature
std::vector<uint8_t> ship_table(SIG_ENTRIES, 1); // Start neutral

// Streaming detector state per set
struct stream_set_t {
    uint64_t prev_addr;
    int32_t deltas[STREAM_HIST_LEN];
    int ptr;
    bool streaming;
};
std::vector<stream_set_t> stream_sets(LLC_SETS);

// Utility: hash PC to signature
inline uint8_t get_sig(uint64_t PC) {
    return champsim_crc2(PC, 0) & (SIG_ENTRIES - 1);
}

// Streaming detection logic
inline void update_streaming(uint32_t set, uint64_t paddr) {
    stream_set_t &st = stream_sets[set];
    if (st.prev_addr != 0) {
        int32_t delta = (int32_t)(paddr - st.prev_addr);
        st.deltas[st.ptr] = delta;
        st.ptr = (st.ptr + 1) % STREAM_HIST_LEN;
        // Count matching deltas
        int cnt = 0;
        int32_t ref = st.deltas[(st.ptr + STREAM_HIST_LEN - 1) % STREAM_HIST_LEN];
        for (int i = 0; i < STREAM_HIST_LEN; i++) if (st.deltas[i] == ref) cnt++;
        st.streaming = (cnt >= STREAM_DELTA_THR);
    }
    st.prev_addr = paddr;
}

void InitReplacementState() {
    for (uint32_t s = 0; s < LLC_SETS; s++)
        for (uint32_t w = 0; w < LLC_WAYS; w++)
            blocks[s][w] = {RRPV_MAX, 1, 0}; // RRPV max, neutral outcome, sig 0

    for (uint32_t s = 0; s < LLC_SETS; s++) {
        stream_sets[s].prev_addr = 0;
        memset(stream_sets[s].deltas, 0, sizeof(stream_sets[s].deltas));
        stream_sets[s].ptr = 0;
        stream_sets[s].streaming = false;
    }

    for (uint32_t i = 0; i < SIG_ENTRIES; i++)
        ship_table[i] = 1; // neutral
}

// Victim selection: highest RRPV, tie-breaker oldest outcome
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Prefer blocks with RRPV_MAX; among them, lowest outcome (least reused)
    int victim = -1;
    int min_outcome = OUTCOME_MAX + 1;
    for (uint32_t w = 0; w < LLC_WAYS; w++) {
        if (blocks[set][w].rrpv == RRPV_MAX) {
            if (blocks[set][w].outcome < min_outcome) {
                min_outcome = blocks[set][w].outcome;
                victim = w;
            }
        }
    }
    if (victim >= 0) return victim;
    // Fallback: oldest RRPV
    for (uint32_t w = 0; w < LLC_WAYS; w++)
        if (blocks[set][w].rrpv == RRPV_MAX) return w;
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
    update_streaming(set, paddr);

    uint8_t sig = get_sig(PC);

    if (hit) {
        // Promote block to MRU
        blocks[set][way].rrpv = RRPV_MRU;
        blocks[set][way].sig = sig;
        // Update outcome counter for this signature
        if (blocks[set][way].outcome < OUTCOME_MAX) blocks[set][way].outcome++;
        if (ship_table[sig] < OUTCOME_MAX) ship_table[sig]++;
    } else {
        // On fill/replace
        bool streaming = stream_sets[set].streaming;
        bool bypass = streaming;

        if (!bypass) {
            // Insert with SHiP-guided RRPV
            uint8_t ins_rrpv = (ship_table[sig] > 0) ? RRPV_MRU : RRPV_LRU;
            blocks[set][way].rrpv = ins_rrpv;
            blocks[set][way].sig = sig;
            blocks[set][way].outcome = ship_table[sig];
        }
        // On replacement: if victim not reused, penalize signature
        uint8_t victim_sig = blocks[set][way].sig;
        if (blocks[set][way].outcome == 0 && ship_table[victim_sig] > OUTCOME_MIN)
            ship_table[victim_sig]--;
    }
    // Periodic decay: every 4096 fills, decay ship_table
    static uint64_t fill_count = 0;
    fill_count++;
    if ((fill_count & 0xFFF) == 0) {
        for (uint32_t i = 0; i < SIG_ENTRIES; i++)
            if (ship_table[i] > 0) ship_table[i]--;
    }
}

void PrintStats() {
    // Print streaming set count and outcome distribution
    int stream_cnt = 0;
    for (auto &st : stream_sets)
        if (st.streaming) stream_cnt++;
    std::cout << "SLSB: Streaming sets flagged = " << stream_cnt << "/" << LLC_SETS << std::endl;

    int reused = 0, not_reused = 0;
    for (uint32_t i = 0; i < SIG_ENTRIES; i++) {
        if (ship_table[i] > 0) reused++;
        else not_reused++;
    }
    std::cout << "SLSB: SHiP signatures reused=" << reused << " not_reused=" << not_reused << std::endl;
}

void PrintStats_Heartbeat() {
    // No periodic stats needed
}