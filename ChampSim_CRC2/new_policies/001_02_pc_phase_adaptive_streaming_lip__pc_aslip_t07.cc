#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- Metadata structures ---
// 2-bit RRPV per block
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// Compact PC phase table: 6-bit signature, 1-bit phase (reuse/streaming)
#define PC_SIG_BITS 6
#define PC_SIG_ENTRIES 1024
struct PCPhaseEntry {
    uint8_t phase; // 1 bit: 0=reuse, 1=streaming/scan
};
PCPhaseEntry pc_phase_table[PC_SIG_ENTRIES];

// Per-block PC signature
uint8_t block_pc_sig[LLC_SETS][LLC_WAYS];

// Streaming detector: per-set last address, last delta, streaming flag
struct StreamDetect {
    uint64_t last_addr;
    int64_t last_delta;
    uint8_t stream_cnt; // 2 bits
    bool is_streaming;
};
StreamDetect stream_detect[LLC_SETS];

// Per-block reuse counter: 2 bits
uint8_t reuse_counter[LLC_SETS][LLC_WAYS];

// DIP-style set-dueling: 64 leader sets, 10-bit PSEL
#define NUM_LEADER_SETS 64
uint32_t leader_sets[NUM_LEADER_SETS];
uint16_t PSEL = 512; // 10 bits, midpoint

// Helper: hash PC to signature
inline uint16_t GetPCSig(uint64_t PC) {
    return (PC ^ (PC >> 6) ^ (PC >> 12)) & ((1 << PC_SIG_BITS) - 1);
}

// Assign leader sets: first 32 for LIP, next 32 for BIP
inline bool IsLIPLeader(uint32_t set) {
    for (int i = 0; i < NUM_LEADER_SETS / 2; ++i)
        if (leader_sets[i] == set) return true;
    return false;
}
inline bool IsBIPLeader(uint32_t set) {
    for (int i = NUM_LEADER_SETS / 2; i < NUM_LEADER_SETS; ++i)
        if (leader_sets[i] == set) return true;
    return false;
}

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv)); // 2-bit RRPV, init to max
    memset(pc_phase_table, 0, sizeof(pc_phase_table));
    memset(block_pc_sig, 0, sizeof(block_pc_sig));
    memset(stream_detect, 0, sizeof(stream_detect));
    memset(reuse_counter, 0, sizeof(reuse_counter));
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
            if (sd.stream_cnt < 3) ++sd.stream_cnt;
        } else {
            if (sd.stream_cnt > 0) --sd.stream_cnt;
        }
        sd.is_streaming = (sd.stream_cnt >= 2);
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
    // Prefer block with max RRPV
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
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

    // --- PC signature ---
    uint16_t pc_sig = GetPCSig(PC);

    // --- On hit ---
    if (hit) {
        rrpv[set][way] = 0; // MRU
        // Mark PC as reuse phase if block reused multiple times
        if (reuse_counter[set][way] < 3) ++reuse_counter[set][way];
        if (reuse_counter[set][way] >= 2)
            pc_phase_table[pc_sig].phase = 0; // reuse phase
        return;
    }

    // --- On fill ---
    block_pc_sig[set][way] = pc_sig;
    reuse_counter[set][way] = 0; // reset reuse

    // --- Set-dueling: determine policy globally ---
    bool use_lip = false;
    if (IsLIPLeader(set)) use_lip = true;
    else if (IsBIPLeader(set)) use_lip = false;
    else use_lip = (PSEL >= 512);

    // --- Choose insertion depth ---
    uint8_t ins_rrpv = 3; // default: LRU

    if (streaming) {
        // Streaming phase: bypass or always insert at LRU
        ins_rrpv = 3;
        pc_phase_table[pc_sig].phase = 1; // mark as streaming
    }
    else if (pc_phase_table[pc_sig].phase == 0) {
        // Reuse phase: use LIP: always insert at LRU, except MRU if high reuse
        if (reuse_counter[set][way] >= 2)
            ins_rrpv = 0; // MRU
        else
            ins_rrpv = 3; // LRU
    }
    else {
        // Streaming/scan phase: use BIP (insert at MRU occasionally), otherwise LRU
        ins_rrpv = (rand() % 32 == 0) ? 0 : 3;
    }

    // For leader sets, update PSEL on hit
    if (IsLIPLeader(set)) {
        if (hit && PSEL < 1023) ++PSEL;
    } else if (IsBIPLeader(set)) {
        if (hit && PSEL > 0) --PSEL;
    }

    rrpv[set][way] = ins_rrpv;
}

// --- Print statistics ---
void PrintStats() {
    std::cout << "PC-ASLIP Policy: PC-phase adaptive LIP/BIP streaming + per-block reuse\n";
}
void PrintStats_Heartbeat() {}