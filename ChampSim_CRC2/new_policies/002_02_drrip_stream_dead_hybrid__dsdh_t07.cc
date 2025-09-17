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
#define RRPV_MAX ((1<<RRPV_BITS)-1)
#define PSEL_BITS 10
#define PSEL_MAX ((1<<PSEL_BITS)-1)
#define SRRIP_INSERT 2
#define BRRIP_INSERT 3
#define BRRIP_BIAS 32 // 1/32 ins at SRRIP, rest at BRRIP

// Leader sets for set-dueling
#define NUM_LEADER_SETS 64
#define LEADER_SET_STRIDE (LLC_SETS/NUM_LEADER_SETS)

// Streaming detector
#define STREAM_HIST_LEN 4
#define STREAM_DELTA_THR 3

// Dead-block: 2b per block
#define DEAD_CTR_BITS 2

struct block_state_t {
    uint8_t rrpv;       // 2b
    uint8_t dead_ctr;   // 2b
};

std::vector<std::vector<block_state_t>> blocks(LLC_SETS, std::vector<block_state_t>(LLC_WAYS));

// DRRIP set-dueling state
std::vector<uint8_t> set_type(LLC_SETS, 0); // 0: follower, 1: SRRIP leader, 2: BRRIP leader
uint16_t PSEL = PSEL_MAX/2;

// Streaming detector state per set
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
        uint32_t s1 = i * LEADER_SET_STRIDE;
        uint32_t s2 = i * LEADER_SET_STRIDE + LEADER_SET_STRIDE/2;
        if (s1 < LLC_SETS) set_type[s1] = 1;  // SRRIP leader
        if (s2 < LLC_SETS) set_type[s2] = 2;  // BRRIP leader
    }
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
        int32_t ref = st.deltas[(st.ptr+STREAM_HIST_LEN-1)%STREAM_HIST_LEN];
        for(int i=0;i<STREAM_HIST_LEN;i++) if(st.deltas[i]==ref) cnt++;
        st.streaming = (cnt >= STREAM_DELTA_THR);
    }
    st.prev_addr = paddr;
}

void InitReplacementState() {
    for(uint32_t s=0; s<LLC_SETS; s++)
        for(uint32_t w=0; w<LLC_WAYS; w++)
            blocks[s][w] = {RRPV_MAX, 0}; // RRPV max, dead_ctr 0

    for(uint32_t s=0; s<LLC_SETS; s++) {
        stream_sets[s].prev_addr = 0;
        memset(stream_sets[s].deltas, 0, sizeof(stream_sets[s].deltas));
        stream_sets[s].ptr = 0;
        stream_sets[s].streaming = false;
    }
    assign_leader_sets();
    PSEL = PSEL_MAX/2;
}

// Victim selection: prefer dead blocks, else highest RRPV
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Dead-block preference
    int victim = -1;
    int min_dead = 5;
    for(int rrpv=RRPV_MAX; rrpv>=0; rrpv--) {
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
            if(blocks[set][w].rrpv == RRPV_MAX) return w;
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

    // DRRIP set-dueling update
    uint8_t stype = set_type[set];
    if(hit) {
        blocks[set][way].rrpv = 0;
        if(blocks[set][way].dead_ctr < ((1<<DEAD_CTR_BITS)-1))
            blocks[set][way].dead_ctr++;
        // Set-dueling: leaders update PSEL
        if(stype == 1 && PSEL < PSEL_MAX) PSEL++;
        else if(stype == 2 && PSEL > 0) PSEL--;
    } else {
        // On fill/replace: streaming detection
        bool streaming = stream_sets[set].streaming;
        bool bypass = false;

        uint8_t ins_rrpv = 0;
        if(streaming) {
            bypass = true; // never insert streaming blocks
        } else {
            // Insertion policy (DRRIP): leader sets fixed, followers use PSEL
            if(stype == 1)      // SRRIP leader
                ins_rrpv = SRRIP_INSERT;
            else if(stype == 2) // BRRIP leader
                ins_rrpv = (rand()%BRRIP_BIAS==0)?SRRIP_INSERT:BRRIP_INSERT;
            else {              // follower
                if(PSEL >= PSEL_MAX/2)
                    ins_rrpv = SRRIP_INSERT;
                else
                    ins_rrpv = (rand()%BRRIP_BIAS==0)?SRRIP_INSERT:BRRIP_INSERT;
            }
        }

        if(!bypass) {
            blocks[set][way].rrpv = ins_rrpv;
            blocks[set][way].dead_ctr = 0;
        }

        // Dead-block feedback: on replacement, if victim dead, don't penalize
        if(blocks[set][way].dead_ctr == 0) {
            // Optional: could adapt insertion policy, but DRRIP already adapts via PSEL
        }
    }

    // Periodic decay: every 4096 fills, decay dead_ctr
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
    std::cout << "DSDH: Final PSEL value = " << PSEL << std::endl;
    // Optional: print streaming set count
    int stream_cnt=0;
    for(auto& st : stream_sets)
        if(st.streaming) stream_cnt++;
    std::cout << "DSDH: Streaming sets flagged = " << stream_cnt << "/" << LLC_SETS << std::endl;
}

void PrintStats_Heartbeat() {
    // No periodic stats needed
}