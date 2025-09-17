#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

//--- SRRIP metadata: 2 bits per block
uint8_t rrpv[LLC_SETS][LLC_WAYS];

//--- Dead-block counter: 2 bits per block
uint8_t dead_ctr[LLC_SETS][LLC_WAYS];

//--- Streaming detector: per-set last address, delta, and stream count
struct StreamDetect {
    uint64_t last_addr;
    int64_t last_delta;
    uint8_t stream_count; // up to 7
};
StreamDetect stream_info[LLC_SETS];

//--- Streaming threshold
#define STREAM_DETECT_THRESHOLD 4

//--- Dead-block decay interval
#define DEAD_DECAY_INTERVAL 4096
uint64_t global_access_ctr = 0;

//--------------------------------------------
// Initialization
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv)); // Distant for all blocks
    memset(dead_ctr, 0, sizeof(dead_ctr));
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        stream_info[set].last_addr = 0;
        stream_info[set].last_delta = 0;
        stream_info[set].stream_count = 0;
    }
    global_access_ctr = 0;
}

//--------------------------------------------
// Find victim in the set (SRRIP)
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Standard RRIP victim selection
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            rrpv[set][way]++;
    }
    return 0; // Should not reach
}

//--------------------------------------------
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
    global_access_ctr++;

    //--- Streaming detection
    StreamDetect &sd = stream_info[set];
    int64_t delta = (sd.last_addr) ? (int64_t)paddr - (int64_t)sd.last_addr : 0;
    bool streaming = false;

    if (sd.last_addr && delta == sd.last_delta && delta != 0) {
        if (sd.stream_count < 7) sd.stream_count++;
    } else {
        sd.stream_count = 0;
    }
    sd.last_addr = paddr;
    sd.last_delta = delta;

    if (sd.stream_count >= STREAM_DETECT_THRESHOLD)
        streaming = true;

    //--- Dead-block counter decay (periodic)
    if ((global_access_ctr & (DEAD_DECAY_INTERVAL - 1)) == 0) {
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            for (uint32_t w = 0; w < LLC_WAYS; ++w)
                if (dead_ctr[s][w] > 0)
                    dead_ctr[s][w]--;
    }

    //--- On hit: promote & reinforce dead-block counter
    if (hit) {
        rrpv[set][way] = 0;
        if (dead_ctr[set][way] < 3)
            dead_ctr[set][way]++;
    } else {
        //--- Streaming: bypass or insert at distant
        if (streaming) {
            rrpv[set][way] = 3; // Insert at distant (or optionally bypass, but here we always insert at distant)
            dead_ctr[set][way] = 0;
        } else {
            //--- Dead-block guided insertion
            if (dead_ctr[set][way] >= 2)
                rrpv[set][way] = 1; // Likely reused soon
            else if (dead_ctr[set][way] == 1)
                rrpv[set][way] = 2; // Medium
            else
                rrpv[set][way] = 3; // Distant
        }
    }
}

//--------------------------------------------
// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "SRRIP + Streaming Bypass + Dead-Block Counter Hybrid: Final statistics." << std::endl;
}

//--------------------------------------------
// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Optionally print streaming set counts, dead-block stats
}