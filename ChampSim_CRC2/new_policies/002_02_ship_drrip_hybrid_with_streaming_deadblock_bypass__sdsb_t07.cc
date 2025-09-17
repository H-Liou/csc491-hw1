#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- DRRIP metadata ---
// 2-bit RRPV per block
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// 64 leader sets for DRRIP set-dueling
#define NUM_LEADER_SETS 64
uint32_t leader_sets[NUM_LEADER_SETS];
uint16_t PSEL = 512; // 10 bits

inline bool IsSRRIPLeader(uint32_t set) {
    for (int i = 0; i < NUM_LEADER_SETS / 2; ++i)
        if (leader_sets[i] == set) return true;
    return false;
}
inline bool IsBRRIPLeader(uint32_t set) {
    for (int i = NUM_LEADER_SETS / 2; i < NUM_LEADER_SETS; ++i)
        if (leader_sets[i] == set) return true;
    return false;
}

// --- SHiP-lite: 6-bit PC signature, 2-bit outcome counter ---
#define SHIP_SIGNATURE_BITS 6
#define SHIP_SIGNATURES (1 << SHIP_SIGNATURE_BITS)
struct SHIPEntry {
    uint8_t reuse_counter; // 2 bits
};
SHIPEntry ship_table[SHIP_SIGNATURES];

// Store signature per block for update
uint8_t block_sig[LLC_SETS][LLC_WAYS];

// --- Streaming detector (per set): small monotonic delta counter ---
struct StreamDetect {
    uint64_t last_addr;
    int64_t last_delta;
    uint8_t stream_count; // 2 bits
    bool is_streaming;
};
StreamDetect stream_detect[LLC_SETS];

// --- Dead-block detector (per block): small saturating counter ---
uint8_t dead_counter[LLC_SETS][LLC_WAYS]; // 2 bits per block

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv)); // Init to max RRPV
    memset(stream_detect, 0, sizeof(stream_detect));
    memset(ship_table, 0, sizeof(ship_table));
    memset(block_sig, 0, sizeof(block_sig));
    memset(dead_counter, 0, sizeof(dead_counter));
    // Assign leader sets: evenly spaced
    for (int i = 0; i < NUM_LEADER_SETS; ++i)
        leader_sets[i] = (LLC_SETS / NUM_LEADER_SETS) * i;
    PSEL = 512;
}

// --- Streaming detector ---
// Returns true if streaming detected for this set
bool DetectStreaming(uint32_t set, uint64_t paddr) {
    StreamDetect &sd = stream_detect[set];
    int64_t delta = paddr - sd.last_addr;
    if (sd.last_addr != 0) {
        if (delta == sd.last_delta && delta != 0) {
            if (sd.stream_count < 3) ++sd.stream_count;
        } else {
            if (sd.stream_count > 0) --sd.stream_count;
        }
        sd.is_streaming = (sd.stream_count >= 2);
    }
    sd.last_delta = delta;
    sd.last_addr = paddr;
    return sd.is_streaming;
}

// --- Victim selection (SRRIP) ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Standard SRRIP victim selection
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (rrpv[set][way] == 3)
                return way;
        }
        // Increment all RRPVs
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] < 3) ++rrpv[set][way];
    }
}

// --- Update replacement state ---
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
    bool streaming = DetectStreaming(set, paddr);

    // --- SHiP signature ---
    uint8_t sig = champsim_crc2(PC) & (SHIP_SIGNATURES - 1);

    // --- Dead-block detector ---
    if (hit) {
        rrpv[set][way] = 0; // MRU on hit
        block_sig[set][way] = sig;
        if (dead_counter[set][way] > 0) --dead_counter[set][way];
        // SHiP: reward reuse
        if (ship_table[block_sig[set][way]].reuse_counter < 3)
            ++ship_table[block_sig[set][way]].reuse_counter;
        // DRRIP leader sets update
        if (IsSRRIPLeader(set)) {
            if (PSEL < 1023) ++PSEL;
        } else if (IsBRRIPLeader(set)) {
            if (PSEL > 0) --PSEL;
        }
        return;
    }

    // --- On fill ---
    // Streaming or dead-block detected: bypass (insert at distant RRPV)
    if (streaming || dead_counter[set][way] >= 2) {
        rrpv[set][way] = 3; // Insert at distant RRPV
        block_sig[set][way] = sig;
        dead_counter[set][way] = 0;
        return;
    }

    // SHiP outcome: if signature shows frequent reuse, insert at MRU
    bool ship_predict_reuse = (ship_table[sig].reuse_counter >= 2);

    // DRRIP insertion selection
    bool use_srrip = false;
    if (IsSRRIPLeader(set)) use_srrip = true;
    else if (IsBRRIPLeader(set)) use_srrip = false;
    else use_srrip = (PSEL >= 512);

    // Final insertion depth decision
    if (ship_predict_reuse) {
        rrpv[set][way] = 0; // MRU: expected reuse
    } else {
        if (use_srrip) {
            rrpv[set][way] = 2; // SRRIP distant
        } else {
            // BRRIP: insert at distant RRPV most of the time
            if ((rand() % 32) == 0)
                rrpv[set][way] = 2; // rare close insert
            else
                rrpv[set][way] = 3;
        }
    }
    block_sig[set][way] = sig;
    dead_counter[set][way] = 0;
}

// --- Dead-block counter update (called externally per eviction) ---
void OnEvict(uint32_t set, uint32_t way) {
    if (dead_counter[set][way] < 3) ++dead_counter[set][way];
    // SHiP: punish non-reuse
    uint8_t sig = block_sig[set][way];
    if (ship_table[sig].reuse_counter > 0)
        --ship_table[sig].reuse_counter;
}

// --- Print statistics ---
void PrintStats() {
    std::cout << "SDSB Policy: SHiP-lite + DRRIP Set-Dueling + Streaming/Deadblock Bypass\n";
}
void PrintStats_Heartbeat() {}