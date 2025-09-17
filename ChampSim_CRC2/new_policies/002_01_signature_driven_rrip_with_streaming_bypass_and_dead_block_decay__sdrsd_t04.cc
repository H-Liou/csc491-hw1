#include <vector>
#include <cstdint>
#include <cstring>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// RRIP constants
#define RRPV_BITS 2
#define RRPV_MAX ((1 << RRPV_BITS) - 1)
#define RRPV_INSERT_SRRIP 2
#define RRPV_INSERT_BRRIP 3
#define RRPV_INSERT_MRU 0

// SHiP-lite constants
#define SHIP_SIG_BITS 6
#define SHIP_SIG_ENTRIES (1 << SHIP_SIG_BITS)
#define SHIP_COUNTER_BITS 2
#define SHIP_COUNTER_MAX ((1 << SHIP_COUNTER_BITS) - 1)

// Streaming detector
#define STREAM_DELTA_HISTORY 4
#define STREAM_DELTA_THRESHOLD 3

// DRRIP set-dueling
#define DRRIP_LEADER_SETS 64
#define DRRIP_PSEL_BITS 10
#define DRRIP_PSEL_MAX ((1 << DRRIP_PSEL_BITS) - 1)
#define DRRIP_SRRIP 0
#define DRRIP_BRRIP 1
#define DRRIP_BRRIP_PROB 32 // Insert at RRPV=2 once every 32 fills

// Dead-block counter
#define DEADBIT_DECAY_INTERVAL 4096

struct BLOCK_META {
    uint8_t rrpv;          // 2 bits
    uint8_t ship_sig;      // 6 bits
    uint8_t deadbit;       // 1 bit
};

struct SHIP_SIG_ENTRY {
    uint8_t reuse_counter; // 2 bits
};

struct STREAM_DETECTOR {
    uint64_t last_addr;
    int64_t delta_history[STREAM_DELTA_HISTORY];
    uint8_t ptr;
};

std::vector<BLOCK_META> block_meta;
std::vector<SHIP_SIG_ENTRY> ship_sig_table;
std::vector<STREAM_DETECTOR> stream_detector;

std::vector<uint16_t> drrip_leader_sets;
uint16_t psel = DRRIP_PSEL_MAX / 2;

uint64_t access_counter = 0;
uint64_t streaming_bypass_fills = 0;
uint64_t deadbit_decay_events = 0;

// Helper: get SHiP signature from PC
inline uint8_t get_ship_sig(uint64_t PC) {
    return (PC ^ (PC >> 3)) & (SHIP_SIG_ENTRIES - 1);
}

// Helper: get block meta index
inline size_t get_block_meta_idx(uint32_t set, uint32_t way) {
    return set * LLC_WAYS + way;
}

// Streaming detection
bool is_streaming_set(uint32_t set, uint64_t curr_addr) {
    STREAM_DETECTOR &sd = stream_detector[set];
    int64_t delta = curr_addr - sd.last_addr;
    if (sd.last_addr != 0) {
        sd.delta_history[sd.ptr] = delta;
        sd.ptr = (sd.ptr + 1) % STREAM_DELTA_HISTORY;
    }
    sd.last_addr = curr_addr;
    int positive = 0, negative = 0, nonzero = 0;
    for (int i = 0; i < STREAM_DELTA_HISTORY; i++) {
        if (sd.delta_history[i] > 0) positive++;
        else if (sd.delta_history[i] < 0) negative++;
        if (sd.delta_history[i] != 0) nonzero++;
    }
    if (nonzero >= STREAM_DELTA_THRESHOLD &&
        (positive >= STREAM_DELTA_THRESHOLD || negative >= STREAM_DELTA_THRESHOLD)) {
        return true;
    }
    return false;
}

// DRRIP set-dueling type for set
uint8_t get_drrip_type(uint32_t set) {
    for (auto ls : drrip_leader_sets) {
        if (set == ls) return DRRIP_SRRIP;
        if (set == ls + LLC_SETS / 2) return DRRIP_BRRIP;
    }
    return (psel >= DRRIP_PSEL_MAX / 2) ? DRRIP_SRRIP : DRRIP_BRRIP;
}

// Initialization
void InitReplacementState() {
    block_meta.resize(LLC_SETS * LLC_WAYS);
    ship_sig_table.resize(SHIP_SIG_ENTRIES);
    stream_detector.resize(LLC_SETS);

    drrip_leader_sets.clear();
    for (uint16_t i = 0; i < DRRIP_LEADER_SETS; i++)
        drrip_leader_sets.push_back(i * (LLC_SETS / DRRIP_LEADER_SETS));

    for (size_t i = 0; i < block_meta.size(); i++) {
        block_meta[i].rrpv = RRPV_MAX;
        block_meta[i].ship_sig = 0;
        block_meta[i].deadbit = 0;
    }
    for (size_t i = 0; i < ship_sig_table.size(); i++) {
        ship_sig_table[i].reuse_counter = 0;
    }
    for (size_t i = 0; i < stream_detector.size(); i++) {
        stream_detector[i].last_addr = 0;
        memset(stream_detector[i].delta_history, 0, sizeof(stream_detector[i].delta_history));
        stream_detector[i].ptr = 0;
    }
}

// Victim selection: RRIP with dead-block priority
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Prefer blocks with deadbit=1 and RRPV==RRPV_MAX
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        size_t idx = get_block_meta_idx(set, way);
        if (block_meta[idx].deadbit == 1)
            return way;
    }
    // Otherwise, RRIP victim selection
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        size_t idx = get_block_meta_idx(set, way);
        if (block_meta[idx].rrpv == RRPV_MAX)
            return way;
    }
    // If none, increment all RRPVs and retry
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        size_t idx = get_block_meta_idx(set, way);
        if (block_meta[idx].rrpv < RRPV_MAX)
            block_meta[idx].rrpv++;
    }
    // Second pass
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        size_t idx = get_block_meta_idx(set, way);
        if (block_meta[idx].rrpv == RRPV_MAX)
            return way;
    }
    // If still none, pick way 0
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
    access_counter++;

    size_t idx = get_block_meta_idx(set, way);
    BLOCK_META &meta = block_meta[idx];

    // Periodic deadbit decay: every DEADBIT_DECAY_INTERVAL accesses, clear all deadbits
    if ((access_counter % DEADBIT_DECAY_INTERVAL) == 0) {
        for (size_t i = 0; i < block_meta.size(); i++)
            block_meta[i].deadbit = 0;
        deadbit_decay_events++;
    }

    // Streaming detection
    bool streaming = is_streaming_set(set, paddr);

    // SHiP signature
    uint8_t sig = get_ship_sig(PC);

    // On cache hit
    if (hit) {
        // Update SHiP reuse counter
        if (ship_sig_table[sig].reuse_counter < SHIP_COUNTER_MAX)
            ship_sig_table[sig].reuse_counter++;
        // Promote block to MRU
        meta.rrpv = RRPV_INSERT_MRU;
        // Clear deadbit (block was reused)
        meta.deadbit = 0;
        // DRRIP PSEL: update on leader sets and hits
        for (auto ls : drrip_leader_sets) {
            if (set == ls && psel < DRRIP_PSEL_MAX) psel++;
            if (set == ls + LLC_SETS / 2 && psel > 0) psel--;
        }
        return;
    }

    // On fill (miss)
    meta.ship_sig = sig;

    // Streaming phase: bypass fill (simulate by setting RRPV=MAX and deadbit=1)
    if (streaming) {
        meta.rrpv = RRPV_MAX;
        meta.deadbit = 1;
        streaming_bypass_fills++;
        return;
    }

    // SHiP strong reuse signature: insert at MRU, deadbit=0
    if (ship_sig_table[sig].reuse_counter >= (SHIP_COUNTER_MAX - 1)) {
        meta.rrpv = RRPV_INSERT_MRU;
        meta.deadbit = 0;
    }
    // DRRIP set-dueling: select SRRIP/BRRIP insertion depth
    else {
        uint8_t drrip_type = get_drrip_type(set);
        if (drrip_type == DRRIP_SRRIP) {
            meta.rrpv = RRPV_INSERT_SRRIP;
        } else { // DRRIP_BRRIP
            if ((rand() % DRRIP_BRRIP_PROB) == 0)
                meta.rrpv = RRPV_INSERT_SRRIP;
            else
                meta.rrpv = RRPV_INSERT_BRRIP;
        }
        meta.deadbit = 1; // Assume dead until proven reused
    }

    // Update SHiP reuse counter: on victim eviction
    uint32_t victim_way = GetVictimInSet(cpu, set, nullptr, PC, paddr, type);
    size_t victim_idx = get_block_meta_idx(set, victim_way);
    uint8_t victim_sig = block_meta[victim_idx].ship_sig;
    if (block_meta[victim_idx].rrpv == RRPV_INSERT_MRU) {
        if (ship_sig_table[victim_sig].reuse_counter < SHIP_COUNTER_MAX)
            ship_sig_table[victim_sig].reuse_counter++;
    } else {
        if (ship_sig_table[victim_sig].reuse_counter > 0)
            ship_sig_table[victim_sig].reuse_counter--;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "SDRSD: Signature-Driven RRIP Streaming Bypass Dead-Block Decay stats\n";
    std::cout << "Total accesses: " << access_counter << "\n";
    std::cout << "Streaming fills bypassed: " << streaming_bypass_fills << "\n";
    std::cout << "Deadbit decay events: " << deadbit_decay_events << "\n";
    size_t streaming_sets = 0;
    for (size_t i = 0; i < stream_detector.size(); i++) {
        if (is_streaming_set(i, stream_detector[i].last_addr)) streaming_sets++;
    }
    std::cout << "Streaming sets detected: " << streaming_sets << "\n";
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    std::cout << "SDRSD heartbeat: accesses=" << access_counter
              << ", streaming_bypass_fills=" << streaming_bypass_fills
              << ", deadbit_decay_events=" << deadbit_decay_events << "\n";
}