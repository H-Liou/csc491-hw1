#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// RRIP metadata: 2 bits/block
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// Per-block PC signature: 6 bits/block
uint8_t block_sig[LLC_SETS][LLC_WAYS];

// SHiP-lite: 2-bit outcome counter per signature (4096 entries)
const uint32_t SHIP_SIG_ENTRIES = 4096;
uint8_t ship_counter[SHIP_SIG_ENTRIES]; // 2 bits per entry

// Streaming detector: 3 bits/set
struct StreamSet {
    uint64_t last_addr;
    uint8_t stride_count; // up to 3
    uint8_t streaming;    // 1 if streaming detected
    uint8_t window;       // streaming window countdown
};
StreamSet stream_sets[LLC_SETS];

// RRIP constants
const uint8_t RRIP_MAX = 3;
const uint8_t RRIP_MRU = 0;
const uint8_t RRIP_DISTANT = 2;

// Streaming window length
const uint8_t STREAM_WIN = 8;

// Helper: hash PC to signature (6 bits)
inline uint16_t get_signature(uint64_t PC) {
    // Use CRC or simple hash
    return champsim_crc2(PC) & 0x3F; // 6 bits
}

// Helper: map signature to SHIP counter index
inline uint32_t sig_index(uint16_t sig) {
    // Direct mapping, 4096 entries
    return sig;
}

// Initialize replacement state
void InitReplacementState() {
    memset(rrpv, RRIP_MAX, sizeof(rrpv));
    memset(block_sig, 0, sizeof(block_sig));
    memset(ship_counter, 1, sizeof(ship_counter)); // Start neutral
    memset(stream_sets, 0, sizeof(stream_sets));
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
    // Streaming: if active, always evict block with RRPV==RRIP_MAX
    if (stream_sets[set].streaming && stream_sets[set].window > 0) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == RRIP_MAX)
                return way;
        // If none, increment RRPV and retry
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] < RRIP_MAX)
                rrpv[set][way]++;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == RRIP_MAX)
                return way;
        return 0;
    }

    // Standard RRIP victim selection
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (rrpv[set][way] == RRIP_MAX)
            return way;
    // If none, increment RRPV and retry
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (rrpv[set][way] < RRIP_MAX)
            rrpv[set][way]++;
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (rrpv[set][way] == RRIP_MAX)
            return way;
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
    // --- Streaming detector ---
    StreamSet &ss = stream_sets[set];
    uint64_t cur_addr = paddr >> 6; // cache line granularity
    int64_t stride = cur_addr - ss.last_addr;
    if (ss.last_addr != 0 && (stride == 1 || stride == -1)) {
        if (ss.stride_count < 3) ss.stride_count++;
        if (ss.stride_count == 3 && !ss.streaming) {
            ss.streaming = 1;
            ss.window = STREAM_WIN;
        }
    } else {
        ss.stride_count = 0;
        ss.streaming = 0;
        ss.window = 0;
    }
    ss.last_addr = cur_addr;
    if (ss.streaming && ss.window > 0)
        ss.window--;

    // --- SHiP signature ---
    uint16_t sig = get_signature(PC);
    uint32_t idx = sig_index(sig);

    // --- RRIP update ---
    if (hit) {
        rrpv[set][way] = RRIP_MRU;
        // On hit, increment SHIP counter for this block's signature
        uint8_t b_sig = block_sig[set][way];
        uint32_t b_idx = sig_index(b_sig);
        if (ship_counter[b_idx] < 3) ship_counter[b_idx]++;
    } else {
        // --- Insertion policy ---
        uint8_t ins_rrpv;
        if (ss.streaming && ss.window > 0) {
            // Streaming detected: insert at RRIP_MAX (bypass)
            ins_rrpv = RRIP_MAX;
        } else {
            // Use SHIP counter for this PC
            if (ship_counter[idx] >= 2) {
                ins_rrpv = RRIP_DISTANT; // likely reused: retain moderately
            } else {
                ins_rrpv = RRIP_MAX; // likely dead: insert at distant
            }
        }
        rrpv[set][way] = ins_rrpv;
        block_sig[set][way] = sig;
        // On miss, decrement SHIP counter for victim's signature
        uint8_t v_sig = block_sig[set][way];
        uint32_t v_idx = sig_index(v_sig);
        if (ship_counter[v_idx] > 0) ship_counter[v_idx]--;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    // Streaming set count
    uint64_t streaming_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (stream_sets[s].streaming)
            streaming_sets++;
    std::cout << "SHiP-SB: Streaming sets at end: " << streaming_sets << std::endl;
    // SHIP counter distribution
    uint64_t reused = 0, dead = 0;
    for (uint32_t i = 0; i < SHIP_SIG_ENTRIES; ++i) {
        if (ship_counter[i] >= 2) reused++;
        else dead++;
    }
    std::cout << "SHiP-SB: SHIP reused sigs: " << reused << ", dead sigs: " << dead << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Optionally print streaming set count or SHIP counter stats
}