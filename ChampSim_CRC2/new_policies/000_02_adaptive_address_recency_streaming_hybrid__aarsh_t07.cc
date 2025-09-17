#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

// Parameters
#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// DIP parameters
#define NUM_LEADER_SETS 64
#define PSEL_MAX 1023
#define LIP_SET 0
#define BIP_SET 1

// Address signature: 4 bits per block, 2-bit reuse counter
#define ADDR_SIG_BITS 4
#define ADDR_SIG_MASK ((1 << ADDR_SIG_BITS)-1)
#define REUSE_BITS 2

// Streaming detector: 4-entry delta history per set
#define STREAM_HIST_LEN 4
#define STREAM_DELTA_THR 3 // if 3+ out of 4 recent accesses have same delta, treat as streaming

// Per-set DIP state
struct dip_set_t {
    bool is_leader;
    uint8_t leader_type; // 0: LIP, 1: BIP
};

// Replacement state
struct block_state_t {
    uint8_t rrpv;        // 2 bits
    uint8_t reuse_ctr;   // 2 bits
    uint8_t addr_sig;    // 4 bits
};

std::vector<std::vector<block_state_t>> blocks(LLC_SETS, std::vector<block_state_t>(LLC_WAYS));

// DIP: leader sets and PSEL
std::vector<dip_set_t> dip_sets(LLC_SETS);
uint16_t psel = PSEL_MAX/2; // 10 bits

// Streaming detector state
struct stream_set_t {
    uint64_t prev_addr;
    int32_t deltas[STREAM_HIST_LEN];
    int ptr;
    bool streaming;
};
std::vector<stream_set_t> stream_sets(LLC_SETS);

// Utility: compute address signature
inline uint8_t addr_signature(uint64_t paddr) {
    // Simple: take bits [12–15] (block aligned), 4 bits
    return (paddr >> 12) & ADDR_SIG_MASK;
}

void InitReplacementState() {
    // DIP: randomly assign leader sets
    for(uint32_t s=0; s<LLC_SETS; s++) {
        dip_sets[s].is_leader = false;
        dip_sets[s].leader_type = 0;
    }
    for(uint32_t i=0; i<NUM_LEADER_SETS/2; i++) {
        dip_sets[i].is_leader = true; dip_sets[i].leader_type = LIP_SET;
        dip_sets[LLC_SETS-1-i].is_leader = true; dip_sets[LLC_SETS-1-i].leader_type = BIP_SET;
    }
    // Blocks
    for(uint32_t s=0; s<LLC_SETS; s++)
        for(uint32_t w=0; w<LLC_WAYS; w++)
            blocks[s][w] = {3, 0, 0}; // RRPV max, reuse 0, sig 0

    // Streaming detector
    for(uint32_t s=0; s<LLC_SETS; s++) {
        stream_sets[s].prev_addr = 0;
        memset(stream_sets[s].deltas, 0, sizeof(stream_sets[s].deltas));
        stream_sets[s].ptr = 0;
        stream_sets[s].streaming = false;
    }
    psel = PSEL_MAX/2;
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

    // Dead-block aware: prefer blocks with reuse_ctr==0
    int victim = -1;
    for(int rrpv=3; rrpv>=0; rrpv--) {
        for(uint32_t w=0; w<LLC_WAYS; w++) {
            if(blocks[set][w].rrpv == rrpv) {
                if(victim < 0 || blocks[set][w].reuse_ctr < blocks[set][victim].reuse_ctr)
                    victim = w;
            }
        }
        if(victim >= 0) break;
    }
    if(victim < 0) victim = 0;
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

    // Address signature
    uint8_t sig = addr_signature(paddr);

    if(hit) {
        // On hit: promote block, increment reuse
        blocks[set][way].rrpv = 0;
        if(blocks[set][way].reuse_ctr < ((1<<REUSE_BITS)-1))
            blocks[set][way].reuse_ctr++;
    } else {
        // On fill/replace
        // DIP: insertion policy selection
        bool is_leader = dip_sets[set].is_leader;
        uint8_t leader_type = dip_sets[set].leader_type;
        uint8_t ipolicy = 0; // 0:LIP, 1:BIP
        if(is_leader)
            ipolicy = leader_type;
        else
            ipolicy = (psel > PSEL_MAX/2) ? LIP_SET : BIP_SET;

        // Streaming-aware insertion
        bool streaming = stream_sets[set].streaming;
        uint8_t ins_rrpv = 3;
        if(streaming) {
            // Streaming: insert at distant RRPV (max), minimize pollution
            ins_rrpv = 3;
        } else {
            // Non-streaming: use reuse info and DIP
            // If address signature has high reuse, protect at MRU; else follow DIP
            bool high_reuse = false;
            for(uint32_t w=0; w<LLC_WAYS; w++)
                if(blocks[set][w].addr_sig == sig && blocks[set][w].reuse_ctr >= 1)
                    high_reuse = true;
            if(high_reuse) {
                ins_rrpv = 0;
            } else if(ipolicy == LIP_SET) {
                ins_rrpv = 3;
            } else { // BIP
                ins_rrpv = (rand()%32 == 0) ? 0 : 3;
            }
        }

        // Insert
        blocks[set][way].rrpv = ins_rrpv;
        blocks[set][way].reuse_ctr = 0;
        blocks[set][way].addr_sig = sig;

        // DIP: update PSEL if replacement was in leader set
        if(is_leader && !streaming) {
            // If hit, increment for LIP; decrement for BIP
            if(leader_type == LIP_SET && hit) {
                if(psel < PSEL_MAX) psel++;
            }
            if(leader_type == BIP_SET && hit) {
                if(psel > 0) psel--;
            }
        }
    }

    // Periodic decay: every 4096 fills, decay reuse counters
    static uint64_t fill_count = 0;
    fill_count++;
    if((fill_count & 0xFFF) == 0) {
        for(uint32_t s=0; s<LLC_SETS; s++)
            for(uint32_t w=0; w<LLC_WAYS; w++)
                if(blocks[s][w].reuse_ctr > 0)
                    blocks[s][w].reuse_ctr--;
    }
}

void PrintStats() {
    std::cout << "AARSH: PSEL=" << psel << std::endl;
}
void PrintStats_Heartbeat() { }