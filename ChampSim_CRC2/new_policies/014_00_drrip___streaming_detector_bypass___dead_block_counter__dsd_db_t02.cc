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

// DRRIP set-dueling
#define NUM_LEADER_SETS 64
#define PSEL_BITS 10
#define PSEL_MAX ((1<<PSEL_BITS)-1)
#define PSEL_INIT (PSEL_MAX/2)

// Streaming detector
#define STREAM_DETECTOR_BITS 8
#define STREAM_WINDOW 8
#define STREAM_THRESHOLD 6

// Dead-block counter
#define DEAD_BITS 2
#define DEAD_MAX ((1<<DEAD_BITS)-1)
#define DEAD_INIT 1
#define DEAD_DECAY_INTERVAL 4096

struct block_state_t {
    uint8_t rrpv;      // 2 bits: RRIP value
    uint8_t dead_cnt;  // 2 bits: dead-block counter
};

std::vector<std::vector<block_state_t>> blocks(LLC_SETS, std::vector<block_state_t>(LLC_WAYS));

// Streaming detector: per set
struct stream_detector_t {
    uint64_t last_addr;
    uint8_t deltas[STREAM_WINDOW];
    uint8_t idx;
    bool streaming;
};
std::vector<stream_detector_t> stream_detectors(LLC_SETS);

// DRRIP set-dueling
std::vector<bool> is_leader_srrip(LLC_SETS, false);
std::vector<bool> is_leader_brrip(LLC_SETS, false);
uint16_t psel = PSEL_INIT;

// Dead-block decay
uint64_t access_counter = 0;

// Helper: assign leader sets
void InitLeaderSets() {
    for (uint32_t i = 0; i < NUM_LEADER_SETS; i++) {
        is_leader_srrip[i] = true;
        is_leader_brrip[LLC_SETS - 1 - i] = true;
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

void InitReplacementState() {
    for(uint32_t s=0; s<LLC_SETS; s++) {
        for(uint32_t w=0; w<LLC_WAYS; w++) {
            blocks[s][w] = {RRPV_MAX, DEAD_INIT};
        }
        stream_detectors[s].last_addr = 0;
        std::fill(stream_detectors[s].deltas, stream_detectors[s].deltas+STREAM_WINDOW, 0);
        stream_detectors[s].idx = 0;
        stream_detectors[s].streaming = false;
    }
    InitLeaderSets();
    psel = PSEL_INIT;
    access_counter = 0;
}

// Find victim: prefer blocks with RRPV==MAX and dead_cnt==0
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // First, try blocks with RRPV==MAX and dead_cnt==0
    for (uint32_t w = 0; w < LLC_WAYS; w++)
        if (blocks[set][w].rrpv == RRPV_MAX && blocks[set][w].dead_cnt == 0)
            return w;
    // Next, blocks with RRPV==MAX and lowest dead_cnt
    uint32_t victim = LLC_WAYS;
    uint8_t min_dead = DEAD_MAX+1;
    for (uint32_t w = 0; w < LLC_WAYS; w++) {
        if (blocks[set][w].rrpv == RRPV_MAX && blocks[set][w].dead_cnt < min_dead) {
            min_dead = blocks[set][w].dead_cnt;
            victim = w;
        }
    }
    if (victim < LLC_WAYS)
        return victim;
    // Otherwise, increment RRPV and repeat
    for (uint32_t w = 0; w < LLC_WAYS; w++)
        if (blocks[set][w].rrpv < RRPV_MAX)
            blocks[set][w].rrpv++;
    return GetVictimInSet(cpu, set, current_set, PC, paddr, type);
}

// DRRIP insertion policy
uint8_t GetInsertionRRPV(uint32_t set) {
    if (is_leader_srrip[set])
        return SRRIP_INSERT;
    if (is_leader_brrip[set])
        return BRRIP_INSERT;
    // Follower sets: use PSEL
    return (psel >= (PSEL_MAX/2)) ? SRRIP_INSERT : BRRIP_INSERT;
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
    access_counter++;
    UpdateStreamingDetector(set, paddr);

    // Dead-block decay (periodic)
    if (access_counter % DEAD_DECAY_INTERVAL == 0) {
        for (uint32_t s = 0; s < LLC_SETS; s++)
            for (uint32_t w = 0; w < LLC_WAYS; w++)
                if (blocks[s][w].dead_cnt > 0)
                    blocks[s][w].dead_cnt--;
    }

    // On hit: set block to MRU, increment dead-block counter
    if (hit) {
        blocks[set][way].rrpv = SRRIP_INSERT;
        if (blocks[set][way].dead_cnt < DEAD_MAX)
            blocks[set][way].dead_cnt++;
        return;
    }

    // Streaming detector: bypass if streaming detected
    if (IsStreaming(set)) {
        // Simulate bypass: set RRPV=MAX, dead_cnt=0
        blocks[set][way].rrpv = RRPV_MAX;
        blocks[set][way].dead_cnt = 0;
        return;
    }

    // DRRIP insertion
    uint8_t ins_rrpv = GetInsertionRRPV(set);
    blocks[set][way].rrpv = ins_rrpv;
    blocks[set][way].dead_cnt = DEAD_INIT;

    // DRRIP set-dueling update
    if (is_leader_srrip[set]) {
        if (hit) {
            if (psel < PSEL_MAX) psel++;
        }
    } else if (is_leader_brrip[set]) {
        if (hit) {
            if (psel > 0) psel--;
        }
    }
}

void PrintStats() {
    int streaming_sets = 0;
    for(uint32_t s=0; s<LLC_SETS; s++)
        if(stream_detectors[s].streaming)
            streaming_sets++;
    std::cout << "DSD-DB: Streaming sets=" << streaming_sets << "/" << LLC_SETS << std::endl;
    std::cout << "DSD-DB: PSEL=" << psel << std::endl;
}

void PrintStats_Heartbeat() {
    // No periodic stats needed
}