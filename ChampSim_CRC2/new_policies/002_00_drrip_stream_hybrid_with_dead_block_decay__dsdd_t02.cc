#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// DRRIP parameters
#define RRPV_BITS 2
#define RRPV_MAX ((1 << RRPV_BITS) - 1)
#define NUM_LEADER_SETS 64
#define PSEL_BITS 10
#define PSEL_MAX ((1 << PSEL_BITS) - 1)

// Streaming detector
#define STREAM_HIST_LEN 4
#define STREAM_DELTA_THR 3

// Dead-block counter
#define DEAD_CTR_BITS 2

struct block_state_t {
    uint8_t rrpv;      // 2 bits
    uint8_t dead_ctr;  // 2 bits
};

std::vector<std::vector<block_state_t>> blocks(LLC_SETS, std::vector<block_state_t>(LLC_WAYS));

// DRRIP set-dueling
std::vector<bool> is_leader_srrip(LLC_SETS, false);
std::vector<bool> is_leader_brrip(LLC_SETS, false);
uint16_t psel = PSEL_MAX / 2;

// Streaming detector state
struct stream_set_t {
    uint64_t prev_addr;
    int32_t deltas[STREAM_HIST_LEN];
    int ptr;
    bool streaming;
};
std::vector<stream_set_t> stream_sets(LLC_SETS);

// Utility: assign leader sets
void assign_leader_sets() {
    for (uint32_t i = 0; i < NUM_LEADER_SETS; i++) {
        is_leader_srrip[i] = true;
        is_leader_brrip[LLC_SETS - 1 - i] = true;
    }
}

// Streaming detection logic
inline void update_streaming(uint32_t set, uint64_t paddr) {
    stream_set_t &st = stream_sets[set];
    if (st.prev_addr != 0) {
        int32_t delta = (int32_t)(paddr - st.prev_addr);
        st.deltas[st.ptr] = delta;
        st.ptr = (st.ptr + 1) % STREAM_HIST_LEN;
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
            blocks[s][w] = {RRPV_MAX, 0};

    for (uint32_t s = 0; s < LLC_SETS; s++) {
        stream_sets[s].prev_addr = 0;
        memset(stream_sets[s].deltas, 0, sizeof(stream_sets[s].deltas));
        stream_sets[s].ptr = 0;
        stream_sets[s].streaming = false;
    }
    assign_leader_sets();
    psel = PSEL_MAX / 2;
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
    // Dead-block aware: prefer blocks with dead_ctr==0, else lowest dead_ctr, else RRIP
    int victim = -1;
    int min_dead = DEAD_CTR_BITS + 1;
    for (int rrpv = RRPV_MAX; rrpv >= 0; rrpv--) {
        for (uint32_t w = 0; w < LLC_WAYS; w++) {
            if (blocks[set][w].rrpv == rrpv) {
                if (blocks[set][w].dead_ctr == 0)
                    return w;
                if (blocks[set][w].dead_ctr < min_dead) {
                    min_dead = blocks[set][w].dead_ctr;
                    victim = w;
                }
            }
        }
        if (victim >= 0) break;
    }
    if (victim < 0) {
        // Fallback: oldest RRPV
        for (uint32_t w = 0; w < LLC_WAYS; w++)
            if (blocks[set][w].rrpv == RRPV_MAX) return w;
        return 0;
    }
    return victim;
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

    // DRRIP insertion policy selection
    bool streaming = stream_sets[set].streaming;
    bool leader_srrip = is_leader_srrip[set];
    bool leader_brrip = is_leader_brrip[set];

    uint8_t ins_rrpv = RRPV_MAX; // default: distant RRPV
    bool bypass = false;

    if (hit) {
        // On hit: promote block, increment dead_ctr
        blocks[set][way].rrpv = 0;
        if (blocks[set][way].dead_ctr < ((1 << DEAD_CTR_BITS) - 1))
            blocks[set][way].dead_ctr++;
    } else {
        // On fill/replace
        if (streaming) {
            // Streaming: bypass with 50% probability, else insert at distant RRPV
            bypass = (rand() % 2 == 0);
            ins_rrpv = RRPV_MAX;
        } else {
            // DRRIP: select insertion policy
            if (leader_srrip)
                ins_rrpv = RRPV_MAX;
            else if (leader_brrip)
                ins_rrpv = (rand() % 32 == 0) ? 0 : RRPV_MAX; // BRRIP: 1/32 MRU, else distant
            else
                ins_rrpv = (psel >= (PSEL_MAX / 2)) ?
                    ((rand() % 32 == 0) ? 0 : RRPV_MAX) : RRPV_MAX;
        }

        if (!bypass) {
            blocks[set][way].rrpv = ins_rrpv;
            blocks[set][way].dead_ctr = 0;
        }

        // DRRIP set-dueling: update PSEL
        if (leader_srrip && !hit && !bypass) {
            if (psel > 0) psel--;
        }
        if (leader_brrip && hit && !bypass) {
            if (psel < PSEL_MAX) psel++;
        }
    }

    // Periodic decay: every 4096 fills, decay dead-block counters
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
    // Print PSEL value and dead-block counter summary
    int dead0 = 0, total = 0;
    for (uint32_t s = 0; s < LLC_SETS; s++)
        for (uint32_t w = 0; w < LLC_WAYS; w++) {
            if (blocks[s][w].dead_ctr == 0) dead0++;
            total++;
        }
    std::cout << "DSDD: PSEL=" << psel << " dead0=" << dead0 << "/" << total << std::endl;
}

void PrintStats_Heartbeat() { }