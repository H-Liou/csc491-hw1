#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

// Parameters
#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// DRRIP set-dueling parameters
#define NUM_LEADER_SETS 64
#define PSEL_MAX 1023
#define SRRIP_SET 0
#define BRRIP_SET 1

// SHiP-lite: signature table
#define SHIP_SIG_BITS 6                // 6 bits per signature (from PC)
#define SHIP_SIG_ENTRIES 2048          // 2K entries, 2-bit counters each
#define SHIP_CNTR_BITS 2
#define SHIP_CNTR_MAX ((1 << SHIP_CNTR_BITS)-1)

// Streaming detector
#define STREAM_HIST_LEN 4
#define STREAM_DELTA_THR 3 // 3+ out of 4 same delta => streaming

// Per-block replacement state
struct block_state_t {
    uint8_t rrpv;            // 2 bits
    uint8_t ship_sig;        // 6 bits
};

std::vector<std::vector<block_state_t>> blocks(LLC_SETS, std::vector<block_state_t>(LLC_WAYS));

// DRRIP leader sets and PSEL
struct drrip_set_t {
    bool is_leader;
    uint8_t leader_type;     // 0: SRRIP, 1: BRRIP
};
std::vector<drrip_set_t> drrip_sets(LLC_SETS);
uint16_t psel = PSEL_MAX/2;

// Streaming detector state
struct stream_set_t {
    uint64_t prev_addr;
    int32_t deltas[STREAM_HIST_LEN];
    int ptr;
    bool streaming;
};
std::vector<stream_set_t> stream_sets(LLC_SETS);

// SHiP signature table: 2048 entries, 2 bits each
std::vector<uint8_t> ship_table(SHIP_SIG_ENTRIES, 0);

// Utility: compute SHiP-lite signature from PC (6 bits)
inline uint8_t ship_signature(uint64_t PC) {
    // Use CRC to spread signatures, then truncate to 6 bits
    return champsim_crc2(PC, 0x1234) & ((1 << SHIP_SIG_BITS)-1);
}

// Utility: compute SHiP table index
inline uint32_t ship_index(uint8_t sig) {
    // Direct mapping
    return sig;
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

// Initialize replacement state
void InitReplacementState() {
    // DRRIP: assign leader sets
    for(uint32_t s=0; s<LLC_SETS; s++) {
        drrip_sets[s].is_leader = false;
        drrip_sets[s].leader_type = 0;
    }
    for(uint32_t i=0; i<NUM_LEADER_SETS/2; i++) {
        drrip_sets[i].is_leader = true; drrip_sets[i].leader_type = SRRIP_SET;
        drrip_sets[LLC_SETS-1-i].is_leader = true; drrip_sets[LLC_SETS-1-i].leader_type = BRRIP_SET;
    }
    // Blocks
    for(uint32_t s=0; s<LLC_SETS; s++)
        for(uint32_t w=0; w<LLC_WAYS; w++)
            blocks[s][w] = {3, 0}; // RRPV max (long re-reference), sig 0

    // Streaming detector
    for(uint32_t s=0; s<LLC_SETS; s++) {
        stream_sets[s].prev_addr = 0;
        memset(stream_sets[s].deltas, 0, sizeof(stream_sets[s].deltas));
        stream_sets[s].ptr = 0;
        stream_sets[s].streaming = false;
    }
    // SHiP table
    std::fill(ship_table.begin(), ship_table.end(), 0);

    psel = PSEL_MAX/2;
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
    // Streaming detection
    update_streaming(set, paddr);

    // Standard SRRIP victim selection: Evict highest RRPV; if tie, random among them
    while (true) {
        for (uint32_t w = 0; w < LLC_WAYS; w++) {
            if (blocks[set][w].rrpv == 3)
                return w;
        }
        // Increment all RRPVs if no block has RRPV==3
        for (uint32_t w = 0; w < LLC_WAYS; w++)
            if (blocks[set][w].rrpv < 3)
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
    // Streaming detection
    update_streaming(set, paddr);

    // SHiP signature
    uint8_t sig = ship_signature(PC);
    uint32_t sig_idx = ship_index(sig);

    if (hit) {
        // On hit: promote block, increment SHiP counter
        blocks[set][way].rrpv = 0;
        if (ship_table[sig_idx] < SHIP_CNTR_MAX)
            ship_table[sig_idx]++;
    } else {
        // On fill/replace

        // Streaming-aware insertion
        bool streaming = stream_sets[set].streaming;
        uint8_t ins_rrpv = 3;

        if(streaming) {
            // Streaming: insert at distant RRPV (max), minimize pollution
            ins_rrpv = 3;
        } else {
            // SHiP-guided insertion: If PC's outcome counter is high, insert at MRU
            if (ship_table[sig_idx] >= SHIP_CNTR_MAX) {
                ins_rrpv = 0;
            } else {
                // DRRIP: insertion policy selection
                bool is_leader = drrip_sets[set].is_leader;
                uint8_t leader_type = drrip_sets[set].leader_type;
                uint8_t ipolicy = 0;
                if(is_leader)
                    ipolicy = leader_type;
                else
                    ipolicy = (psel > PSEL_MAX/2) ? SRRIP_SET : BRRIP_SET;

                if(ipolicy == SRRIP_SET)
                    ins_rrpv = 2; // "long" but not max (SRRIP)
                else
                    ins_rrpv = (rand()%32 == 0) ? 2 : 3; // BRRIP: insert at 2 rarely, mostly at 3
            }
        }

        // Update block state
        blocks[set][way].rrpv = ins_rrpv;
        blocks[set][way].ship_sig = sig;

        // On fill: decay SHiP table for evicted block's signature, if it had poor reuse
        uint8_t ev_sig = blocks[set][way].ship_sig;
        uint32_t ev_idx = ship_index(ev_sig);
        if (ship_table[ev_idx] > 0 && ins_rrpv == 3)
            ship_table[ev_idx]--;

        // DRRIP: update PSEL if replacement was in leader set and not streaming
        if(drrip_sets[set].is_leader && !streaming) {
            // If hit, increment for SRRIP; decrement for BRRIP
            if(drrip_sets[set].leader_type == SRRIP_SET && hit) {
                if(psel < PSEL_MAX) psel++;
            }
            if(drrip_sets[set].leader_type == BRRIP_SET && hit) {
                if(psel > 0) psel--;
            }
        }
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "SLS-DRRIP: PSEL=" << psel << std::endl;
}
void PrintStats_Heartbeat() { }