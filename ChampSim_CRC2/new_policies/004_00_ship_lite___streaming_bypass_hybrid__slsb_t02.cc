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

// RRPV parameters
#define RRPV_BITS 2
#define RRPV_MAX ((1 << RRPV_BITS) - 1)
#define MRU_INSERT 0
#define LRU_INSERT RRPV_MAX

// Streaming detector
#define STREAM_HIST_LEN 4
#define STREAM_DELTA_THR 3

// Dead-block counter
#define DEAD_BITS 2
#define DEAD_MAX ((1 << DEAD_BITS) - 1)

// Per-block state
struct block_state_t {
    uint8_t rrpv;         // 2b
    uint8_t dead_ctr;     // 2b
    uint8_t sig;          // 6b
};

std::vector<std::vector<block_state_t>> blocks(LLC_SETS, std::vector<block_state_t>(LLC_WAYS));

// SHiP-lite signature table (shared across sets)
struct ship_sig_t {
    uint8_t outcome;      // 2b
};
std::vector<ship_sig_t> ship_table(SIG_ENTRIES);

// Streaming detector state per set
struct stream_set_t {
    uint64_t prev_addr;
    int32_t deltas[STREAM_HIST_LEN];
    int ptr;
    bool streaming;
};
std::vector<stream_set_t> stream_sets(LLC_SETS);

// Utility: get SHiP signature from PC
inline uint8_t get_signature(uint64_t PC) {
    // Simple CRC6 hash for PC
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
        for (int i = 0; i < STREAM_HIST_LEN; i++)
            if (st.deltas[i] == ref) cnt++;
        st.streaming = (cnt >= STREAM_DELTA_THR);
    }
    st.prev_addr = paddr;
}

void InitReplacementState() {
    for (uint32_t s = 0; s < LLC_SETS; s++)
        for (uint32_t w = 0; w < LLC_WAYS; w++)
            blocks[s][w] = {RRPV_MAX, 0, 0}; // RRPV max, dead_ctr 0, sig 0

    for (uint32_t s = 0; s < LLC_SETS; s++) {
        stream_sets[s].prev_addr = 0;
        memset(stream_sets[s].deltas, 0, sizeof(stream_sets[s].deltas));
        stream_sets[s].ptr = 0;
        stream_sets[s].streaming = false;
    }
    for (uint32_t i = 0; i < SIG_ENTRIES; i++)
        ship_table[i].outcome = OUTCOME_MIN;
}

// Victim selection: prefer RRPV==RRPV_MAX, break ties by dead_ctr
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    int victim = -1;
    int min_dead = DEAD_MAX + 1;
    // First, look for block with RRPV==RRPV_MAX and dead_ctr==0
    for (uint32_t w = 0; w < LLC_WAYS; w++) {
        if (blocks[set][w].rrpv == RRPV_MAX && blocks[set][w].dead_ctr == 0)
            return w;
    }
    // Next, block with RRPV==RRPV_MAX and lowest dead_ctr
    for (uint32_t w = 0; w < LLC_WAYS; w++) {
        if (blocks[set][w].rrpv == RRPV_MAX) {
            if (blocks[set][w].dead_ctr < min_dead) {
                min_dead = blocks[set][w].dead_ctr;
                victim = w;
            }
        }
    }
    if (victim >= 0) return victim;
    // Fallback: block with highest RRPV
    uint32_t max_rrpv = 0;
    for (uint32_t w = 0; w < LLC_WAYS; w++)
        if (blocks[set][w].rrpv > max_rrpv) {
            max_rrpv = blocks[set][w].rrpv;
            victim = w;
        }
    if (victim >= 0) return victim;
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

    uint8_t sig = get_signature(PC);

    if (hit) {
        // On hit: promote block, increment dead_ctr, increment SHiP outcome
        blocks[set][way].rrpv = MRU_INSERT;
        if (blocks[set][way].dead_ctr < DEAD_MAX)
            blocks[set][way].dead_ctr++;
        if (ship_table[sig].outcome < OUTCOME_MAX)
            ship_table[sig].outcome++;
    } else {
        // On fill/replace
        bool streaming = stream_sets[set].streaming;
        bool bypass = false;
        uint8_t ins_rrpv = LRU_INSERT;

        if (streaming) {
            bypass = true; // streaming: bypass cache
        } else {
            // Use SHiP outcome to choose insertion depth
            if (ship_table[sig].outcome >= OUTCOME_MAX - 1)
                ins_rrpv = MRU_INSERT; // high reuse: insert MRU
            else
                ins_rrpv = LRU_INSERT; // low reuse: insert LRU
        }

        if (!bypass) {
            blocks[set][way].rrpv = ins_rrpv;
            blocks[set][way].dead_ctr = 0;
            blocks[set][way].sig = sig;
        }
        // On replacement: if victim block was not reused, decrement SHiP outcome
        uint8_t victim_sig = blocks[set][way].sig;
        if (ship_table[victim_sig].outcome > OUTCOME_MIN)
            ship_table[victim_sig].outcome--;
    }

    // Periodic decay: every 4096 fills, decay dead_ctr
    static uint64_t fill_count = 0;
    fill_count++;
    if ((fill_count & 0xFFF) == 0) {
        for (uint32_t s = 0; s < LLC_SETS; s++)
            for (uint32_t w = 0; w < LLC_WAYS; w++)
                if (blocks[s][w].dead_ctr > 0)
                    blocks[s][w].dead_ctr--;
    }
}

void PrintStats() {
    // Print SHiP outcome histogram
    int high_reuse = 0, low_reuse = 0;
    for (uint32_t i = 0; i < SIG_ENTRIES; i++) {
        if (ship_table[i].outcome >= OUTCOME_MAX - 1) high_reuse++;
        if (ship_table[i].outcome <= OUTCOME_MIN + 1) low_reuse++;
    }
    std::cout << "SLSB: SHiP high-reuse sigs = " << high_reuse << "/" << SIG_ENTRIES << std::endl;
    std::cout << "SLSB: SHiP low-reuse sigs = " << low_reuse << "/" << SIG_ENTRIES << std::endl;
    // Streaming sets flagged
    int stream_cnt = 0;
    for (auto &st : stream_sets)
        if (st.streaming) stream_cnt++;
    std::cout << "SLSB: Streaming sets flagged = " << stream_cnt << "/" << LLC_SETS << std::endl;
}

void PrintStats_Heartbeat() {
    // No periodic stats needed
}