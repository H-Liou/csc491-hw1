#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- SHiP-lite metadata: per-block signature, per-signature outcome ---
struct BlockMeta {
    uint8_t rrpv;      // 2 bits
    uint8_t sig;       // 6 bits: PC signature
};
BlockMeta meta[LLC_SETS][LLC_WAYS];

// Signature outcome table: 1024 entries x 4 bits = 4096 bytes
#define SIG_TABLE_SIZE 1024
uint8_t sig_table[SIG_TABLE_SIZE]; // 4 bits per entry

// Streaming detector: last address, last delta, 2-bit confidence per set
struct StreamDetect {
    uint64_t last_addr;
    int64_t last_delta;
    uint8_t stream_conf; // 2 bits
};
StreamDetect stream_meta[LLC_SETS];

// Helper: hash PC to 6-bit signature
inline uint8_t GetSignature(uint64_t PC) {
    // Simple hash: xor bits, mod 64
    return ((PC >> 2) ^ (PC >> 8) ^ (PC >> 16)) & 0x3F;
}

// Helper: map signature to sig_table index
inline uint16_t SigTableIdx(uint8_t sig) {
    // 6 bits signature, replicate for 1024 entries (16x each)
    return sig | ((sig & 0x3F) << 4); // Spread to 0..1023
}

// Streaming detector: returns true if stream detected in this set
inline bool IsStreaming(uint32_t set, uint64_t paddr) {
    StreamDetect &sd = stream_meta[set];
    int64_t delta = paddr - sd.last_addr;
    bool is_stream = false;
    if (sd.last_addr != 0) {
        if (delta == sd.last_delta && delta != 0) {
            if (sd.stream_conf < 3) sd.stream_conf++;
        } else {
            if (sd.stream_conf > 0) sd.stream_conf--;
        }
        if (sd.stream_conf >= 2) is_stream = true;
    }
    sd.last_delta = delta;
    sd.last_addr = paddr;
    return is_stream;
}

// Initialize replacement state
void InitReplacementState() {
    memset(meta, 0, sizeof(meta));
    memset(sig_table, 0, sizeof(sig_table));
    memset(stream_meta, 0, sizeof(stream_meta));
}

// Find victim in the set (prefer invalid, else RRPV==3)
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (!current_set[way].valid)
            return way;
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (meta[set][way].rrpv == 3)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (meta[set][way].rrpv < 3)
                meta[set][way].rrpv++;
    }
    return 0; // Should not reach
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
    bool is_stream = IsStreaming(set, paddr);

    // --- SHiP-lite signature ---
    uint8_t sig = GetSignature(PC);
    uint16_t idx = SigTableIdx(sig);

    // --- On hit: promote to MRU, update outcome ---
    if (hit) {
        meta[set][way].rrpv = 0;
        // Reward signature outcome
        if (sig_table[idx] < 15) sig_table[idx]++;
        return;
    }

    // --- On miss/fill: streaming bypass ---
    if (is_stream) {
        // Streaming: do not insert (bypass) if possible, else insert at distant
        meta[set][way].rrpv = 3;
        meta[set][way].sig = sig;
        return;
    }

    // --- SHiP-lite insertion depth ---
    // If signature outcome >= 8, insert at MRU (RRPV=0)
    // If outcome <= 3, insert at distant (RRPV=3)
    // Else, insert at mid (RRPV=2)
    uint8_t ins_rrpv = 2;
    if (sig_table[idx] >= 8)
        ins_rrpv = 0;
    else if (sig_table[idx] <= 3)
        ins_rrpv = 3;
    else
        ins_rrpv = 2;

    meta[set][way].rrpv = ins_rrpv;
    meta[set][way].sig = sig;

    // --- On victim: penalize old signature outcome ---
    // Only if victim_addr is valid (simulate: always penalize previous line's signature)
    uint8_t victim_sig = meta[set][way].sig;
    uint16_t victim_idx = SigTableIdx(victim_sig);
    if (sig_table[victim_idx] > 0) sig_table[victim_idx]--;
}

// Print end-of-simulation statistics
void PrintStats() {
    uint32_t stream_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (stream_meta[s].stream_conf >= 2) stream_sets++;
    uint32_t hot_sigs = 0;
    for (uint32_t i = 0; i < SIG_TABLE_SIZE; ++i)
        if (sig_table[i] >= 8) hot_sigs++;
    std::cout << "SHiP-Stream-Lite: streaming sets=" << stream_sets << "/" << LLC_SETS
              << ", hot signatures=" << hot_sigs << "/" << SIG_TABLE_SIZE << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // No periodic decay needed
}