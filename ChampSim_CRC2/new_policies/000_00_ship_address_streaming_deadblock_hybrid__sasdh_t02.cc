#include <vector>
#include <cstdint>
#include <cstring>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- Metadata structures ---
// 2-bit RRPV per block
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// SHiP-lite: 6-bit PC signature table, 2-bit outcome counter
#define SHIP_SIG_BITS 6
#define SHIP_SIG_ENTRIES 1024
struct SHIPEntry {
    uint8_t counter; // 2 bits
};
SHIPEntry ship_table[SHIP_SIG_ENTRIES];

// Per-block PC signature
uint8_t block_pc_sig[LLC_SETS][LLC_WAYS];

// Streaming detector: per-set last address, delta, streaming flag
struct StreamDetect {
    uint64_t last_addr;
    int64_t last_delta;
    uint8_t stream_count; // 2 bits
    bool is_streaming;
};
StreamDetect stream_detect[LLC_SETS];

// Dead-block counter: 2 bits per block
uint8_t dead_block[LLC_SETS][LLC_WAYS];

// SRRIP set-dueling: 64 leader sets, 10-bit PSEL
#define NUM_LEADER_SETS 64
uint32_t leader_sets[NUM_LEADER_SETS];
uint16_t PSEL = 512; // 10 bits, midpoint

// Helper: hash PC to SHiP signature
inline uint16_t GetPCSig(uint64_t PC) {
    return (PC ^ (PC >> 6) ^ (PC >> 12)) & ((1 << SHIP_SIG_BITS) - 1);
}

// Helper: assign leader sets (first 32 for SRRIP, next 32 for BRRIP)
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

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv)); // 2-bit RRPV, init to max
    memset(ship_table, 0, sizeof(ship_table));
    memset(block_pc_sig, 0, sizeof(block_pc_sig));
    memset(stream_detect, 0, sizeof(stream_detect));
    memset(dead_block, 0, sizeof(dead_block));
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

// --- Victim selection ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Prefer blocks with dead_block==3 (dead), then max RRPV
    for (uint32_t way = 0; way < LLC_WAYS; ++way) {
        if (dead_block[set][way] == 3)
            return way;
    }
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
    uint16_t pc_sig = GetPCSig(PC);

    // --- Dead-block counter decay (every 256 accesses per set) ---
    static uint32_t access_counter[LLC_SETS] = {0};
    if (++access_counter[set] % 256 == 0) {
        for (uint32_t w = 0; w < LLC_WAYS; ++w)
            if (dead_block[set][w] > 0) --dead_block[set][w];
    }

    // --- On hit ---
    if (hit) {
        rrpv[set][way] = 0; // MRU
        // SHiP: increment outcome counter for PC
        if (ship_table[pc_sig].counter < 3) ++ship_table[pc_sig].counter;
        // Dead-block: increment reuse
        if (dead_block[set][way] < 3) ++dead_block[set][way];
        return;
    }

    // --- On fill ---
    // Set block's PC signature
    block_pc_sig[set][way] = pc_sig;

    // Dead-block: reset on fill
    dead_block[set][way] = 0;

    // --- Set-dueling: choose insertion policy ---
    bool use_srrip = false;
    if (IsSRRIPLeader(set)) use_srrip = true;
    else if (IsBRRIPLeader(set)) use_srrip = false;
    else use_srrip = (PSEL >= 512);

    // --- SHiP outcome counter for PC ---
    uint8_t ship_ctr = ship_table[pc_sig].counter;

    // --- Insertion depth decision ---
    uint8_t ins_rrpv = 2; // default SRRIP
    if (streaming) {
        // Streaming: bypass (don't insert) or insert at distant RRPV
        ins_rrpv = 3;
    } else if (ship_ctr >= 2) {
        // Strong reuse: insert at MRU
        ins_rrpv = 0;
    } else if (!use_srrip) {
        // BRRIP: insert at distant RRPV with high probability
        ins_rrpv = (rand() % 32 == 0) ? 2 : 3;
    }
    rrpv[set][way] = ins_rrpv;

    // --- Update PSEL for leader sets ---
    if (IsSRRIPLeader(set)) {
        if (hit) { if (PSEL < 1023) ++PSEL; }
    } else if (IsBRRIPLeader(set)) {
        if (hit) { if (PSEL > 0) --PSEL; }
    }
}

// --- Print statistics ---
void PrintStats() {
    std::cout << "SASDH Policy: SHiP-lite + Streaming Detector + DeadBlock + SRRIP-dueling\n";
}
void PrintStats_Heartbeat() {}