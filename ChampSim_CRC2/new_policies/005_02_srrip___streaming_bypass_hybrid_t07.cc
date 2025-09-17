#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// SRRIP/BRRIP definitions
#define RRPV_BITS 2
#define RRPV_MAX ((1 << RRPV_BITS) - 1)
#define PSEL_BITS 10
#define PSEL_MAX ((1 << PSEL_BITS) - 1)
#define DUEL_LEADER_SETS 32
#define STREAM_DETECT_WINDOW 8

struct LINE_REPL_META {
    uint8_t rrpv; // 2 bits
};

std::vector<LINE_REPL_META> repl_meta(LLC_SETS * LLC_WAYS);

uint16_t PSEL = PSEL_MAX / 2;
std::vector<uint8_t> is_srrip_leader(LLC_SETS, 0);
std::vector<uint8_t> is_brrip_leader(LLC_SETS, 0);

// Streaming detector per set: store last STREAM_DETECT_WINDOW address deltas
struct STREAM_SET_DETECT {
    uint64_t last_addr;
    int8_t deltas[STREAM_DETECT_WINDOW];
    int delta_ptr;
    bool streaming;
};
std::vector<STREAM_SET_DETECT> stream_detect(LLC_SETS);

// Helper: update streaming detector for a set
void update_streaming_detector(uint32_t set, uint64_t paddr) {
    STREAM_SET_DETECT &sd = stream_detect[set];
    int8_t delta = (int8_t)((paddr >> 6) - (sd.last_addr >> 6)); // 64B blocks
    sd.last_addr = paddr;
    sd.deltas[sd.delta_ptr] = delta;
    sd.delta_ptr = (sd.delta_ptr + 1) % STREAM_DETECT_WINDOW;

    // Heuristic: streaming if last N deltas are equal and |delta| <= 2
    bool stream = true;
    int8_t ref = sd.deltas[0];
    for (int i = 1; i < STREAM_DETECT_WINDOW; ++i) {
        if (sd.deltas[i] != ref || abs(sd.deltas[i]) > 2) {
            stream = false;
            break;
        }
    }
    sd.streaming = stream;
}

// Initialize replacement state
void InitReplacementState() {
    for (uint32_t s = 0; s < LLC_SETS; ++s) {
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            uint32_t idx = s * LLC_WAYS + w;
            repl_meta[idx].rrpv = RRPV_MAX; // all lines start as long re-use
        }
        // Streaming detector
        stream_detect[s].last_addr = 0;
        memset(stream_detect[s].deltas, 0, sizeof(stream_detect[s].deltas));
        stream_detect[s].delta_ptr = 0;
        stream_detect[s].streaming = false;
    }
    // Set-dueling leader sets
    for (uint32_t i = 0; i < DUEL_LEADER_SETS; ++i) {
        is_srrip_leader[i] = 1;
        is_brrip_leader[LLC_SETS - 1 - i] = 1;
    }
    PSEL = PSEL_MAX / 2;
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
    // Streaming: If set is streaming, always bypass (never insert), so pick LRU but caller must not insert
    if (stream_detect[set].streaming)
        return LLC_WAYS; // special value: bypass

    // Otherwise, find line with RRPV == MAX
    uint32_t base = set * LLC_WAYS;
    for (uint32_t rrpv_val = RRPV_MAX; rrpv_val <= RRPV_MAX; ++rrpv_val) {
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            if (repl_meta[base + w].rrpv == rrpv_val)
                return w;
        }
        // Otherwise, increment all RRPVs and retry
        for (uint32_t w = 0; w < LLC_WAYS; ++w)
            if (repl_meta[base + w].rrpv < RRPV_MAX)
                repl_meta[base + w].rrpv++;
    }
    // Fallback (should never happen)
    return 0;
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
    update_streaming_detector(set, paddr);

    // Streaming: If set is streaming, bypass insertion/update completely
    if (stream_detect[set].streaming) {
        // No update to repl_meta, no insertion
        return;
    }

    uint32_t idx = set * LLC_WAYS + way;
    // On hit: promote to MRU (set RRPV=0)
    if (hit) {
        repl_meta[idx].rrpv = 0;
    } else {
        // On miss: choose insertion policy via set-dueling
        bool srrip_mode = false, brrip_mode = false;
        if (is_srrip_leader[set]) srrip_mode = true;
        if (is_brrip_leader[set]) brrip_mode = true;
        if (!srrip_mode && !brrip_mode)
            srrip_mode = (PSEL >= (PSEL_MAX / 2));
        // SRRIP: insert with RRPV=2; BRRIP: insert with RRPV=3 (long re-use), but only 1/32 of time, else RRPV=2
        uint8_t ins_rrpv = 2;
        if (brrip_mode) {
            ins_rrpv = ((rand() % 32) == 0) ? 2 : 3;
        }
        repl_meta[idx].rrpv = ins_rrpv;
    }

    // PSEL update: only on leader sets, and only on demand accesses (type==0)
    if (is_srrip_leader[set]) {
        if (hit && type == 0 && PSEL < PSEL_MAX) PSEL++;
    }
    if (is_brrip_leader[set]) {
        if (hit && type == 0 && PSEL > 0) PSEL--;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "SRRIP + Streaming Bypass Hybrid stats\n";
    int streaming_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (stream_detect[s].streaming) streaming_sets++;
    std::cout << "Streaming-detected sets: " << streaming_sets << " / " << LLC_SETS << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // No-op
}