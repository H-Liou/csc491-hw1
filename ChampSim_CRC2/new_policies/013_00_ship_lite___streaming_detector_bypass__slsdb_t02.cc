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
#define STREAM_DETECTOR_BITS 8 // per set
#define STREAM_WINDOW 8        // number of recent deltas to track
#define STREAM_THRESHOLD 6     // if >=6/8 deltas are same, treat as streaming

struct block_state_t {
    uint8_t rrpv;       // 2 bits: RRIP value
    uint16_t signature; // 6 bits: PC signature
};

std::vector<std::vector<block_state_t>> blocks(LLC_SETS, std::vector<block_state_t>(LLC_WAYS));

// SHiP-lite table: 2048 entries, 2 bits each
std::vector<uint8_t> ship_table(SHIP_SIG_ENTRIES, SHIP_COUNTER_INIT);

// Streaming detector: per set, track last STREAM_WINDOW address deltas
struct stream_detector_t {
    uint64_t last_addr;
    uint8_t deltas[STREAM_WINDOW];
    uint8_t idx;
    bool streaming;
};
std::vector<stream_detector_t> stream_detectors(LLC_SETS);

inline uint16_t get_signature(uint64_t PC) {
    return (PC ^ (PC >> 2) ^ (PC >> 5)) & SHIP_SIG_MASK;
}

void InitReplacementState() {
    for(uint32_t s=0; s<LLC_SETS; s++) {
        for(uint32_t w=0; w<LLC_WAYS; w++) {
            blocks[s][w] = {RRPV_MAX, 0}; // LRU, no signature
        }
        stream_detectors[s].last_addr = 0;
        std::fill(stream_detectors[s].deltas, stream_detectors[s].deltas+STREAM_WINDOW, 0);
        stream_detectors[s].idx = 0;
        stream_detectors[s].streaming = false;
    }
    std::fill(ship_table.begin(), ship_table.end(), SHIP_COUNTER_INIT);
}

// Find victim in the set (standard RRIP)
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

// Streaming detector update and query
void UpdateStreamingDetector(uint32_t set, uint64_t paddr) {
    stream_detector_t &sd = stream_detectors[set];
    uint8_t delta = (sd.last_addr == 0) ? 0 : (uint8_t)((paddr >> 6) - (sd.last_addr >> 6)); // block granularity
    sd.deltas[sd.idx] = delta;
    sd.idx = (sd.idx + 1) % STREAM_WINDOW;
    sd.last_addr = paddr;

    // Count most common delta
    uint8_t counts[256] = {0};
    for(int i=0; i<STREAM_WINDOW; i++)
        counts[sd.deltas[i]]++;
    uint8_t max_count = *std::max_element(counts, counts+256);
    sd.streaming = (max_count >= STREAM_THRESHOLD && delta != 0);
}

bool IsStreaming(uint32_t set) {
    return stream_detectors[set].streaming;
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
    uint16_t sig = get_signature(PC);

    // Update streaming detector
    UpdateStreamingDetector(set, paddr);

    if (hit) {
        // On hit: set block to MRU, increment SHiP counter
        blocks[set][way].rrpv = SRRIP_INSERT;
        blocks[set][way].signature = sig;
        if (ship_table[sig] < SHIP_COUNTER_MAX)
            ship_table[sig]++;
        return;
    }

    // On fill/replace: SHiP outcome update for victim block
    uint16_t victim_sig = blocks[set][way].signature;
    if (ship_table[victim_sig] > 0)
        ship_table[victim_sig]--;

    // Streaming detector: bypass if streaming detected
    if (IsStreaming(set)) {
        // Do not insert block (simulate bypass by setting RRPV=RRPV_MAX so it will be replaced immediately)
        blocks[set][way].rrpv = RRPV_MAX;
        blocks[set][way].signature = sig;
        return;
    }

    // Otherwise, SHiP-guided insertion
    uint8_t ins_rrpv;
    if (ship_table[sig] >= (SHIP_COUNTER_MAX/2)) {
        ins_rrpv = SRRIP_INSERT;
    } else {
        ins_rrpv = BRRIP_INSERT;
    }
    blocks[set][way].rrpv = ins_rrpv;
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
    int streaming_sets = 0;
    for(uint32_t s=0; s<LLC_SETS; s++)
        if(stream_detectors[s].streaming)
            streaming_sets++;
    std::cout << "SLSDB: SHiP high=" << ship_high << " low=" << ship_low << std::endl;
    std::cout << "SLSDB: Streaming sets=" << streaming_sets << "/" << LLC_SETS << std::endl;
}

void PrintStats_Heartbeat() {
    // No periodic stats needed
}