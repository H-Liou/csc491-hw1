#include <vector>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// RRIP parameters
#define RRPV_BITS 2
#define RRPV_MAX ((1 << RRPV_BITS) - 1)
#define SRRIP_INSERT 1
#define BRRIP_INSERT 3
#define BRRIP_BIAS_PROB 32 // Insert at distant RRPV with 1/32 probability

#define PSEL_BITS 10
#define PSEL_MAX ((1 << PSEL_BITS) - 1)
#define PSEL_INIT (PSEL_MAX / 2)
#define NUM_LEADER_SETS 32
#define SRRIP_LEADER_SET_INTERVAL 64
#define BRRIP_LEADER_SET_INTERVAL 64

// Streaming detector
#define STREAM_DETECT_LEN 3 // streak for streaming
struct StreamDetector {
    uint32_t last_addr_low;
    uint32_t last_delta;
    uint8_t streak;
    bool streaming;
};

struct LineMeta {
    uint8_t rrpv; // 2 bits
};

LineMeta line_meta[LLC_SETS][LLC_WAYS];
StreamDetector stream_table[LLC_SETS];
bool is_srrip_leader[LLC_SETS];
bool is_brrip_leader[LLC_SETS];
uint16_t psel;

// Initialization
void InitReplacementState() {
    std::memset(line_meta, 0, sizeof(line_meta));
    std::memset(stream_table, 0, sizeof(stream_table));
    std::memset(is_srrip_leader, 0, sizeof(is_srrip_leader));
    std::memset(is_brrip_leader, 0, sizeof(is_brrip_leader));
    psel = PSEL_INIT;
    // Assign leader sets for SRRIP and BRRIP
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i) {
        is_srrip_leader[i * SRRIP_LEADER_SET_INTERVAL] = true;
        is_brrip_leader[i * BRRIP_LEADER_SET_INTERVAL + 32] = true;
    }
    // Initialize per-line metadata
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            line_meta[set][way].rrpv = RRPV_MAX;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        stream_table[set].streaming = false;
}

// Streaming detector: address delta streak
bool update_streaming(uint32_t set, uint64_t paddr) {
    StreamDetector &sd = stream_table[set];
    uint32_t addr_low = paddr & 0xFFFFF;
    uint32_t delta = addr_low - sd.last_addr_low;
    bool streaming = false;
    if (sd.streak == 0) {
        sd.last_delta = delta;
        sd.streak = 1;
    } else if (delta == sd.last_delta && delta != 0) {
        sd.streak++;
        if (sd.streak >= STREAM_DETECT_LEN)
            streaming = true;
    } else {
        sd.last_delta = delta;
        sd.streak = 1;
    }
    sd.last_addr_low = addr_low;
    sd.streaming = streaming;
    return streaming;
}

// Find victim (SRRIP): RRPV==MAX, bump others
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (line_meta[set][way].rrpv == RRPV_MAX)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (line_meta[set][way].rrpv < RRPV_MAX)
                line_meta[set][way].rrpv++;
    }
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
    bool streaming = update_streaming(set, paddr);

    // DRRIP insertion policy selection
    bool use_srrip;
    if (is_srrip_leader[set])
        use_srrip = true;
    else if (is_brrip_leader[set])
        use_srrip = false;
    else
        use_srrip = (psel >= PSEL_INIT);

    // On cache fill
    if (!hit) {
        // Streaming detected: bypass fill
        if (streaming) {
            line_meta[set][way].rrpv = RRPV_MAX; // Immediately evict
            return;
        }
        // DRRIP: SRRIP insert at RRPV=SRRIP_INSERT, BRRIP at RRPV=BRRIP_INSERT (biased)
        if (use_srrip)
            line_meta[set][way].rrpv = SRRIP_INSERT;
        else {
            // BRRIP: insert at BRRIP_INSERT (RRPV=3) with low probability, else SRRIP_INSERT
            if ((rand() % BRRIP_BIAS_PROB) == 0)
                line_meta[set][way].rrpv = BRRIP_INSERT;
            else
                line_meta[set][way].rrpv = SRRIP_INSERT;
        }
    } else {
        // On hit: promote to MRU
        line_meta[set][way].rrpv = 0;
    }

    // Set-dueling PSEL update
    if (is_srrip_leader[set]) {
        if (hit && psel < PSEL_MAX) psel++;
        else if (!hit && psel > 0) psel--;
    } else if (is_brrip_leader[set]) {
        if (hit && psel > 0) psel--;
        else if (!hit && psel < PSEL_MAX) psel++;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "ADRIP-CSB Policy: Adaptive DRRIP with Compact Streaming Bypass" << std::endl;
    uint64_t total_fills = 0, streaming_bypassed = 0, mru_promotes = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            total_fills++;
            if (stream_table[set].streaming && line_meta[set][way].rrpv == RRPV_MAX)
                streaming_bypassed++;
            if (line_meta[set][way].rrpv == 0)
                mru_promotes++;
        }
    std::cout << "Fraction streaming bypasses: "
              << (double)streaming_bypassed / total_fills << std::endl;
    std::cout << "Fraction MRU promotes: "
              << (double)mru_promotes / total_fills << std::endl;
    std::cout << "PSEL value: " << psel << "/" << PSEL_MAX << std::endl;
}

void PrintStats_Heartbeat() {}