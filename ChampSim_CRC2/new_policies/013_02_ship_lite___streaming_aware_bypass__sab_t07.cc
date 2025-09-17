#include <vector>
#include <cstdint>
#include <iostream>
#include <algorithm>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// RRIP parameters
#define RRPV_BITS 2
#define RRPV_MAX ((1<<RRPV_BITS)-1)
#define SRRIP_INSERT 0
#define BRRIP_INSERT (RRPV_MAX-1)

// SHiP-lite parameters
#define SHIP_SIG_BITS 6
#define SHIP_SIG_ENTRIES 2048
#define SHIP_SIG_MASK (SHIP_SIG_ENTRIES-1)
#define SHIP_COUNTER_BITS 2
#define SHIP_COUNTER_MAX ((1<<SHIP_COUNTER_BITS)-1)
#define SHIP_COUNTER_INIT 1

// Streaming detector parameters
struct stream_state_t {
    uint64_t last_addr;
    int64_t last_delta;
    uint8_t is_streaming; // 1 if streaming detected, 0 otherwise
    uint16_t stride_count; // count of consecutive accesses with same delta
};
std::vector<stream_state_t> stream_table(LLC_SETS);

// Per-block state
struct block_state_t {
    uint8_t rrpv;       // 2 bits: RRIP value
    uint16_t signature; // 6 bits: PC signature
};
std::vector<std::vector<block_state_t>> blocks(LLC_SETS, std::vector<block_state_t>(LLC_WAYS));

// SHiP-lite table: 2048 entries, 2 bits each
std::vector<uint8_t> ship_table(SHIP_SIG_ENTRIES, SHIP_COUNTER_INIT);

const uint16_t STREAM_DETECT_LEN = 8; // how many strides to declare streaming

inline uint16_t get_signature(uint64_t PC) {
    return (PC ^ (PC >> 2) ^ (PC >> 5)) & SHIP_SIG_MASK;
}

void InitReplacementState() {
    for(uint32_t s=0; s<LLC_SETS; s++) {
        for(uint32_t w=0; w<LLC_WAYS; w++) {
            blocks[s][w] = {RRPV_MAX, 0}; // LRU, no signature
        }
        stream_table[s] = {0, 0, 0, 0}; // reset streaming detector
    }
    std::fill(ship_table.begin(), ship_table.end(), SHIP_COUNTER_INIT);
}

// Victim selection: standard RRIP
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    while (true) {
        for (uint32_t w = 0; w < LLC_WAYS; w++)
            if (blocks[set][w].rrpv == RRPV_MAX)
                return w;
        for (uint32_t w = 0; w < LLC_WAYS; w++)
            if (blocks[set][w].rrpv < RRPV_MAX)
                blocks[set][w].rrpv++;
    }
}

// Update streaming detector: checks for monotonic stride
void UpdateStreamDetector(uint32_t set, uint64_t paddr) {
    auto& st = stream_table[set];
    int64_t delta = (int64_t)paddr - (int64_t)st.last_addr;
    if (st.last_addr != 0) {
        if (delta == st.last_delta && delta != 0) {
            st.stride_count++;
        } else {
            st.stride_count = 1;
            st.last_delta = delta;
        }
        if (st.stride_count >= STREAM_DETECT_LEN)
            st.is_streaming = 1;
        else if (st.stride_count <= 2)
            st.is_streaming = 0;
    } else {
        st.stride_count = 1;
        st.last_delta = 0;
        st.is_streaming = 0;
    }
    st.last_addr = paddr;
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
    uint16_t sig = get_signature(PC);

    // Update streaming detector
    UpdateStreamDetector(set, paddr);

    if (hit) {
        // On hit: set block to MRU, increment SHiP counter
        blocks[set][way].rrpv = SRRIP_INSERT;
        blocks[set][way].signature = sig;
        if (ship_table[sig] < SHIP_COUNTER_MAX)
            ship_table[sig]++;
        return;
    }

    // On fill/replace: update SHiP outcome for victim block
    uint16_t victim_sig = blocks[set][way].signature;
    if (ship_table[victim_sig] > 0)
        ship_table[victim_sig]--;

    // Decide insertion policy
    if (stream_table[set].is_streaming) {
        // Streaming detected: bypass (do not insert at all) with 50% probability, else BRRIP
        // To keep deterministic for benchmarking, alternate even/odd fills
        static uint64_t stream_fill_toggle = 0;
        stream_fill_toggle++;
        if (stream_fill_toggle % 2 == 0) {
            // Bypass: set RRPV to max so it's first victim
            blocks[set][way].rrpv = RRPV_MAX;
        } else {
            // Insert at distant RRPV
            blocks[set][way].rrpv = BRRIP_INSERT;
        }
    } else if (ship_table[sig] >= (SHIP_COUNTER_MAX/2)) {
        // SHiP says likely reused: insert at MRU
        blocks[set][way].rrpv = SRRIP_INSERT;
    } else {
        // Default: insert at distant RRPV
        blocks[set][way].rrpv = BRRIP_INSERT;
    }
    blocks[set][way].signature = sig;
}

void PrintStats() {
    int ship_high = 0, ship_low = 0;
    for(size_t i=0; i<ship_table.size(); i++) {
        if(ship_table[i] >= (SHIP_COUNTER_MAX/2))
            ship_high++;
        else
            ship_low++;
    }
    int stream_sets = 0;
    for(uint32_t s=0; s<LLC_SETS; s++)
        if(stream_table[s].is_streaming)
            stream_sets++;
    std::cout << "SAB: SHiP high=" << ship_high << " low=" << ship_low 
              << " streaming_sets=" << stream_sets << std::endl;
}

void PrintStats_Heartbeat() {
    // No periodic stats needed
}