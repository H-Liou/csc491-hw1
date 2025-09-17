#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// SHiP-lite parameters
#define SHIP_SIG_BITS 5 // 5 bits PC signature
#define SHIP_SIG_ENTRIES 2048 // 2K-entry global table
#define SHIP_SIG_MASK ((1 << SHIP_SIG_BITS)-1)
#define SHIP_OUTCOME_BITS 2 // 2-bit outcome counter

// Streaming detector parameters
#define STREAM_HIST_LEN 4
#define STREAM_DELTA_THR 3 // 3+ out of 4 same delta => streaming

// Per-block replacement state
struct block_state_t {
    uint8_t rrpv;        // 2 bits
    uint8_t ship_sig;    // 5 bits
};

// Per-set streaming detector
struct stream_set_t {
    uint64_t prev_addr;
    int32_t deltas[STREAM_HIST_LEN];
    int ptr;
    bool streaming;
};
std::vector<stream_set_t> stream_sets(LLC_SETS);

// SHiP-lite global table: 2K entries, 2 bits each
std::vector<uint8_t> ship_table(SHIP_SIG_ENTRIES, 1); // init to weakly dead

// Per-block state
std::vector<std::vector<block_state_t>> blocks(LLC_SETS, std::vector<block_state_t>(LLC_WAYS));

// Utility: compute SHiP signature from PC (bits [5:9])
inline uint8_t ship_signature(uint64_t PC) {
    return (PC >> 5) & SHIP_SIG_MASK;
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

void InitReplacementState() {
    // Blocks
    for(uint32_t s=0; s<LLC_SETS; s++)
        for(uint32_t w=0; w<LLC_WAYS; w++)
            blocks[s][w] = {3, 0}; // RRPV max, sig 0

    // Streaming detector
    for(uint32_t s=0; s<LLC_SETS; s++) {
        stream_sets[s].prev_addr = 0;
        memset(stream_sets[s].deltas, 0, sizeof(stream_sets[s].deltas));
        stream_sets[s].ptr = 0;
        stream_sets[s].streaming = false;
    }

    // SHiP table
    for(uint32_t i=0; i<SHIP_SIG_ENTRIES; i++)
        ship_table[i] = 1; // weakly dead
}

// Find victim: SRRIP, prefer blocks with RRPV==3
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

    // Standard SRRIP victim selection
    while (true) {
        for (uint32_t w = 0; w < LLC_WAYS; w++) {
            if (blocks[set][w].rrpv == 3)
                return w;
        }
        // Increment RRPV of all blocks
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

    uint8_t sig = ship_signature(PC);
    blocks[set][way].ship_sig = sig;

    // Streaming phase: bypass insertion
    if (stream_sets[set].streaming) {
        // Do not insert into cache (simulate by setting RRPV=3, so will be evicted soon)
        blocks[set][way].rrpv = 3;
        // No SHiP update for bypassed blocks
        return;
    }

    // SHiP-lite insertion policy
    uint8_t outcome = ship_table[sig];
    if (hit) {
        // On hit: promote block, increment outcome (max 3)
        blocks[set][way].rrpv = 0;
        if (ship_table[sig] < 3)
            ship_table[sig]++;
    } else {
        // On fill/replace: insert at MRU if outcome >=2, else at distant RRPV
        blocks[set][way].rrpv = (outcome >= 2) ? 0 : 3;
    }

    // Periodic decay: every 4096 fills, decay SHiP outcome counters
    static uint64_t fill_count = 0;
    fill_count++;
    if ((fill_count & 0xFFF) == 0) {
        for (uint32_t i = 0; i < SHIP_SIG_ENTRIES; i++)
            if (ship_table[i] > 0)
                ship_table[i]--;
    }
}

void PrintStats() {
    // Print SHiP table summary
    int reused = 0, dead = 0;
    for (uint32_t i = 0; i < SHIP_SIG_ENTRIES; i++) {
        if (ship_table[i] >= 2) reused++;
        else dead++;
    }
    std::cout << "SLSBH: SHiP reused=" << reused << " dead=" << dead << std::endl;
}
void PrintStats_Heartbeat() { }