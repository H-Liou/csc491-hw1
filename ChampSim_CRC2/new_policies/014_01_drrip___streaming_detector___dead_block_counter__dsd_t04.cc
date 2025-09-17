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

// DRRIP set-dueling parameters
#define PSEL_BITS 10
#define PSEL_MAX ((1<<PSEL_BITS)-1)
#define NUM_LEADER_SETS 32
#define LEADER_SET_INTERVAL (LLC_SETS / NUM_LEADER_SETS)
#define SRRIP_LEADER_SET_OFFSET 0
#define BRRIP_LEADER_SET_OFFSET (LEADER_SET_INTERVAL/2)

// Streaming detector parameters
#define STREAM_DETECTOR_BITS 8 // per set
#define STREAM_WINDOW 8
#define STREAM_THRESHOLD 6

// Dead-block counter
#define DEAD_COUNTER_BITS 2
#define DEAD_COUNTER_MAX ((1<<DEAD_COUNTER_BITS)-1)
#define DEAD_DECAY_INTERVAL 4096 // periodic decay

struct block_state_t {
    uint8_t rrpv;         // 2 bits
    uint8_t dead_counter; // 2 bits
};

std::vector<std::vector<block_state_t>> blocks(LLC_SETS, std::vector<block_state_t>(LLC_WAYS));

// DRRIP PSEL
uint16_t psel = PSEL_MAX/2;

// Streaming detector: per set
struct stream_detector_t {
    uint64_t last_addr;
    uint8_t deltas[STREAM_WINDOW];
    uint8_t idx;
    bool streaming;
};
std::vector<stream_detector_t> stream_detectors(LLC_SETS);

// For dead-block decay
uint64_t access_count = 0;

void InitReplacementState() {
    for(uint32_t s=0; s<LLC_SETS; s++) {
        for(uint32_t w=0; w<LLC_WAYS; w++) {
            blocks[s][w] = {RRPV_MAX, 0};
        }
        stream_detectors[s].last_addr = 0;
        std::fill(stream_detectors[s].deltas, stream_detectors[s].deltas+STREAM_WINDOW, 0);
        stream_detectors[s].idx = 0;
        stream_detectors[s].streaming = false;
    }
    psel = PSEL_MAX/2;
    access_count = 0;
}

// Identify leader sets for SRRIP and BRRIP
inline bool is_srrip_leader_set(uint32_t set) {
    return ((set % LEADER_SET_INTERVAL) == SRRIP_LEADER_SET_OFFSET);
}
inline bool is_brrip_leader_set(uint32_t set) {
    return ((set % LEADER_SET_INTERVAL) == BRRIP_LEADER_SET_OFFSET);
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
    uint8_t delta = (sd.last_addr == 0) ? 0 : (uint8_t)((paddr >> 6) - (sd.last_addr >> 6));
    sd.deltas[sd.idx] = delta;
    sd.idx = (sd.idx + 1) % STREAM_WINDOW;
    sd.last_addr = paddr;

    uint8_t counts[256] = {0};
    for(int i=0; i<STREAM_WINDOW; i++)
        counts[sd.deltas[i]]++;
    uint8_t max_count = *std::max_element(counts, counts+256);
    sd.streaming = (max_count >= STREAM_THRESHOLD && delta != 0);
}

bool IsStreaming(uint32_t set) {
    return stream_detectors[set].streaming;
}

// DRRIP insertion policy selection
uint8_t SelectInsertionRRPV(uint32_t set) {
    // Leader sets force SRRIP or BRRIP
    if (is_srrip_leader_set(set))
        return SRRIP_INSERT;
    if (is_brrip_leader_set(set))
        return BRRIP_INSERT;
    // Follower sets use PSEL
    return (psel >= (PSEL_MAX/2)) ? SRRIP_INSERT : BRRIP_INSERT;
}

// Dead-block counter decay
void DecayDeadCounters() {
    for(uint32_t s=0; s<LLC_SETS; s++)
        for(uint32_t w=0; w<LLC_WAYS; w++)
            if (blocks[s][w].dead_counter > 0)
                blocks[s][w].dead_counter--;
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
    access_count++;
    if (access_count % DEAD_DECAY_INTERVAL == 0)
        DecayDeadCounters();

    // Update streaming detector
    UpdateStreamingDetector(set, paddr);

    // Dead-block counter update
    if (hit) {
        // On hit: set block to MRU, reset dead counter
        blocks[set][way].rrpv = SRRIP_INSERT;
        blocks[set][way].dead_counter = 0;
        // DRRIP PSEL update for leader sets
        if (is_srrip_leader_set(set) && psel < PSEL_MAX)
            psel++;
        else if (is_brrip_leader_set(set) && psel > 0)
            psel--;
        return;
    } else {
        // On miss: increment dead counter of victim block
        if (blocks[set][way].dead_counter < DEAD_COUNTER_MAX)
            blocks[set][way].dead_counter++;
    }

    // Streaming detector: bypass if streaming detected
    if (IsStreaming(set)) {
        // Bypass: set RRPV=RRPV_MAX so it is replaced immediately
        blocks[set][way].rrpv = RRPV_MAX;
        blocks[set][way].dead_counter = DEAD_COUNTER_MAX;
        return;
    }

    // Otherwise, DRRIP insertion, but bias with dead-block counter
    uint8_t ins_rrpv = SelectInsertionRRPV(set);
    // If victim block is likely dead, insert at distant RRPV
    if (blocks[set][way].dead_counter >= (DEAD_COUNTER_MAX/2))
        ins_rrpv = BRRIP_INSERT;
    blocks[set][way].rrpv = ins_rrpv;
    blocks[set][way].dead_counter = 0;
}

// Print end-of-simulation statistics
void PrintStats() {
    int streaming_sets = 0;
    for(uint32_t s=0; s<LLC_SETS; s++)
        if(stream_detectors[s].streaming)
            streaming_sets++;
    int dead_blocks = 0;
    for(uint32_t s=0; s<LLC_SETS; s++)
        for(uint32_t w=0; w<LLC_WAYS; w++)
            if(blocks[s][w].dead_counter >= (DEAD_COUNTER_MAX/2))
                dead_blocks++;
    std::cout << "DSD: Streaming sets=" << streaming_sets << "/" << LLC_SETS << std::endl;
    std::cout << "DSD: Dead blocks=" << dead_blocks << "/" << (LLC_SETS*LLC_WAYS) << std::endl;
    std::cout << "DSD: PSEL=" << psel << "/" << PSEL_MAX << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // No periodic stats needed
}