#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

// Parameters
#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// SHiP-lite: 5-bit PC signature, 2-bit outcome counter
#define SHIP_SIG_BITS 5
#define SHIP_SIG_MASK ((1 << SHIP_SIG_BITS)-1)
#define SHIP_CTR_BITS 2
#define SHIP_TABLE_SIZE (1 << SHIP_SIG_BITS)

// Streaming detector: 4-entry delta history per set
#define STREAM_HIST_LEN 4
#define STREAM_DELTA_THR 3 // if 3+ out of 4 recent accesses have same delta, treat as streaming

// Dead-block: 2-bit reuse counter per block
#define DEAD_CTR_BITS 2

struct block_state_t {
    uint8_t rrpv;         // 2 bits
    uint8_t dead_ctr;     // 2 bits
    uint8_t ship_sig;     // 5 bits
};

std::vector<std::vector<block_state_t>> blocks(LLC_SETS, std::vector<block_state_t>(LLC_WAYS));

// SHiP-lite outcome table
std::vector<uint8_t> ship_table(SHIP_TABLE_SIZE, 1); // 2-bit counters, initialized to weakly reused

// Streaming detector state
struct stream_set_t {
    uint64_t prev_addr;
    int32_t deltas[STREAM_HIST_LEN];
    int ptr;
    bool streaming;
};
std::vector<stream_set_t> stream_sets(LLC_SETS);

// Utility: compute SHiP signature (bits [5:9] of PC)
inline uint8_t ship_signature(uint64_t PC) {
    return (PC >> 5) & SHIP_SIG_MASK;
}

void InitReplacementState() {
    for(uint32_t s=0; s<LLC_SETS; s++)
        for(uint32_t w=0; w<LLC_WAYS; w++)
            blocks[s][w] = {3, 0, 0}; // RRPV max, dead_ctr 0, sig 0

    for(uint32_t s=0; s<LLC_SETS; s++) {
        stream_sets[s].prev_addr = 0;
        memset(stream_sets[s].deltas, 0, sizeof(stream_sets[s].deltas));
        stream_sets[s].ptr = 0;
        stream_sets[s].streaming = false;
    }
    std::fill(ship_table.begin(), ship_table.end(), 1);
}

// Streaming detection logic
inline void update_streaming(uint32_t set, uint64_t paddr) {
    stream_set_t &st = stream_sets[set];
    if(st.prev_addr != 0) {
        int32_t delta = (int32_t)(paddr - st.prev_addr);
        st.deltas[st.ptr] = delta;
        st.ptr = (st.ptr + 1) % STREAM_HIST_LEN;
        // Check if most recent deltas are equal
        int cnt = 0;
        int32_t ref = st.deltas[(st.ptr+STREAM_HIST_LEN-1)%STREAM_HIST_LEN];
        for(int i=0;i<STREAM_HIST_LEN;i++) if(st.deltas[i]==ref) cnt++;
        st.streaming = (cnt >= STREAM_DELTA_THR);
    }
    st.prev_addr = paddr;
}

uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Streaming detection
    update_streaming(set, paddr);

    // Dead-block aware: prefer blocks with dead_ctr==0, else lowest dead_ctr, else RRIP
    int victim = -1;
    int min_dead = 5;
    for(int rrpv=3; rrpv>=0; rrpv--) {
        for(uint32_t w=0; w<LLC_WAYS; w++) {
            if(blocks[set][w].rrpv == rrpv) {
                if(blocks[set][w].dead_ctr == 0)
                    return w;
                if(blocks[set][w].dead_ctr < min_dead) {
                    min_dead = blocks[set][w].dead_ctr;
                    victim = w;
                }
            }
        }
        if(victim >= 0) break;
    }
    if(victim < 0) {
        // Fallback: oldest RRPV
        for(uint32_t w=0; w<LLC_WAYS; w++)
            if(blocks[set][w].rrpv == 3) return w;
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
    // Streaming detection
    update_streaming(set, paddr);

    uint8_t sig = ship_signature(PC);

    if(hit) {
        // On hit: promote block, increment dead_ctr, update SHiP outcome
        blocks[set][way].rrpv = 0;
        if(blocks[set][way].dead_ctr < ((1<<DEAD_CTR_BITS)-1))
            blocks[set][way].dead_ctr++;
        if(ship_table[sig] < ((1<<SHIP_CTR_BITS)-1))
            ship_table[sig]++;
    } else {
        // On fill/replace
        bool streaming = stream_sets[set].streaming;
        uint8_t ins_rrpv = 3;
        bool bypass = false;

        if(streaming) {
            // Streaming: bypass cache with 50% probability, else insert at distant RRPV
            bypass = (rand()%2 == 0);
            ins_rrpv = 3;
        } else {
            // Non-streaming: use SHiP prediction
            if(ship_table[sig] >= 2) {
                // High reuse: insert at MRU
                ins_rrpv = 0;
            } else {
                // Low reuse: insert at distant RRPV
                ins_rrpv = 3;
            }
        }

        if(!bypass) {
            blocks[set][way].rrpv = ins_rrpv;
            blocks[set][way].dead_ctr = 0;
            blocks[set][way].ship_sig = sig;
        }

        // On replacement, update SHiP outcome for victim block
        uint8_t victim_sig = blocks[set][way].ship_sig;
        if(blocks[set][way].dead_ctr == 0 && ship_table[victim_sig] > 0)
            ship_table[victim_sig]--;
    }

    // Periodic decay: every 4096 fills, decay dead-block counters
    static uint64_t fill_count = 0;
    fill_count++;
    if((fill_count & 0xFFF) == 0) {
        for(uint32_t s=0; s<LLC_SETS; s++)
            for(uint32_t w=0; w<LLC_WAYS; w++)
                if(blocks[s][w].dead_ctr > 0)
                    blocks[s][w].dead_ctr--;
    }
}

void PrintStats() {
    // Print SHiP table summary
    int reused=0, total=0;
    for(auto ctr : ship_table) {
        if(ctr >= 2) reused++;
        total++;
    }
    std::cout << "SLSDH: SHiP reused sigs=" << reused << "/" << total << std::endl;
}
void PrintStats_Heartbeat() { }