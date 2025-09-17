#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- RRIP per line ---
static uint8_t rrpv[LLC_SETS][LLC_WAYS];

// --- SHiP-lite: 4-bit signature per PC (low 14 bits), 2-bit outcome ---
#define SIGNATURE_BITS 14
#define SIGNATURE_ENTRIES (1 << SIGNATURE_BITS)
struct ship_entry_t {
    uint8_t outcome; // 2 bits: 0=dead, 1=neutral, 2=hot
};
static ship_entry_t ship_table[SIGNATURE_ENTRIES];

// --- Streaming Detector: per set, track last address delta, 8-bit counter ---
struct stream_detector_t {
    int64_t last_addr;
    int64_t last_delta;
    uint8_t stride_count;
};
static stream_detector_t stream_table[LLC_SETS];

// --- Set-dueling for SRRIP vs BRRIP ---
#define PSEL_BITS 10
#define PSEL_MAX ((1 << PSEL_BITS) - 1)
static uint16_t psel_counter = PSEL_MAX / 2;
#define LEADER_SETS 64
static bool is_srrip_leader(uint32_t set) { return (set % 128) < (LEADER_SETS/2); }
static bool is_brrip_leader(uint32_t set) { return (set % 128) >= (LEADER_SETS/2); }

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv));
    memset(ship_table, 0, sizeof(ship_table));
    memset(stream_table, 0, sizeof(stream_table));
    psel_counter = PSEL_MAX / 2;
}

// Returns 4-bit PC signature
inline uint16_t get_signature(uint64_t PC) {
    return (PC ^ (PC >> 2)) & (SIGNATURE_ENTRIES - 1);
}

// Streaming detector: returns true if streaming (3+ consecutive same delta)
inline bool is_streaming(uint32_t set, uint64_t paddr) {
    int64_t addr = (int64_t)paddr;
    stream_detector_t &sd = stream_table[set];
    int64_t delta = addr - sd.last_addr;
    bool streaming = false;
    if (sd.last_addr != 0) {
        if (delta == sd.last_delta && delta != 0) {
            if (sd.stride_count < 255) ++sd.stride_count;
        } else {
            sd.stride_count = 1;
            sd.last_delta = delta;
        }
        if (sd.stride_count >= 3) streaming = true;
    } else {
        sd.stride_count = 1;
        sd.last_delta = 0;
    }
    sd.last_addr = addr;
    return streaming;
}

// Victim selection: SRRIP
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // 1. Look for RRPV==3
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (rrpv[set][way] == 3) return way;
    // 2. Increment all RRPV and repeat
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) rrpv[set][way] = std::min(rrpv[set][way] + 1, 3U);
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3) return way;
    }
}

// Block insertion: choose RRPV based on SHiP signature, streaming detector, and set-dueling
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
    // Update streaming detector
    bool streaming = is_streaming(set, paddr);

    uint16_t sig = get_signature(PC);
    uint8_t outcome = ship_table[sig].outcome;

    // On hit: promote to MRU
    if (hit) {
        rrpv[set][way] = 0;
        if (outcome < 2) ship_table[sig].outcome++;
        return;
    }

    // Set-dueling: leader sets update psel based on hit/miss
    if (is_srrip_leader(set)) {
        if (!hit && psel_counter < PSEL_MAX) ++psel_counter;
    } else if (is_brrip_leader(set)) {
        if (!hit && psel_counter > 0) --psel_counter;
    }

    // Decide insertion policy
    uint8_t insert_rrpv;
    if (streaming) {
        insert_rrpv = 3; // bypass streaming
    } else if (outcome == 2) {
        insert_rrpv = 0; // hot signature: near MRU
    } else if (outcome == 1) {
        insert_rrpv = 2; // warm signature: mid
    } else {
        // cold signature: set-dueling between SRRIP and BRRIP
        if (is_srrip_leader(set)) insert_rrpv = 2;
        else if (is_brrip_leader(set)) insert_rrpv = ((rand() % 32) == 0) ? 2 : 3; // BRRIP: insert distant most of time
        else insert_rrpv = (psel_counter >= PSEL_MAX/2) ? 2 : (((rand() % 32) == 0) ? 2 : 3);
    }

    rrpv[set][way] = insert_rrpv;

    // On miss, penalize cold signatures
    if (!hit && outcome > 0) ship_table[sig].outcome--;
}

// End-of-simulation statistics
void PrintStats() {
    std::cout << "HSAS-RRIP: Hybrid Signature-Address Streaming RRIP statistics (metadata < 48KiB)" << std::endl;
}

void PrintStats_Heartbeat() {
    // Optional: add periodic stats if desired
}