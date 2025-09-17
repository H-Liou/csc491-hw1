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
#define RRPV_INSERT_MRU 0
#define RRPV_INSERT_LRU RRPV_MAX

// SHiP-lite constants
#define SHIP_SIG_BITS 6
#define SHIP_SIG_ENTRIES (1 << SHIP_SIG_BITS)
#define SHIP_COUNTER_BITS 2
#define SHIP_COUNTER_MAX ((1 << SHIP_COUNTER_BITS) - 1)

// Streaming detector
#define STREAM_DELTA_HISTORY 4
#define STREAM_DELTA_THRESHOLD 3 // 3/4 monotonic deltas triggers streaming

// DIP (LIP/BIP) set-dueling
#define DIP_LEADER_SETS 64
#define DIP_PSEL_BITS 10
#define DIP_PSEL_MAX ((1 << DIP_PSEL_BITS) - 1)
#define DIP_LIP 0
#define DIP_BIP 1
#define DIP_BIP_PROB 32 // Insert at LRU once every 32 fills (otherwise MRU)

struct BLOCK_META {
    uint8_t rrpv;          // 2 bits
    uint8_t ship_sig;      // 6 bits
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

std::vector<uint16_t> dip_leader_sets;
uint16_t psel = DIP_PSEL_MAX / 2;

uint64_t access_counter = 0;
uint64_t streaming_bypass_fills = 0;

// Helper: get SHiP signature from PC
inline uint8_t get_ship_sig(uint64_t PC) {
    return (PC ^ (PC >> 3)) & (SHIP_SIG_ENTRIES - 1);
}

// Helper: get block meta index
inline size_t get_block_meta_idx(uint32_t set, uint32_t way) {
    return set * LLC_WAYS + way;
}

// Helper: streaming detection
bool is_streaming_set(uint32_t set, uint64_t curr_addr) {
    STREAM_DETECTOR &sd = stream_detector[set];
    int64_t delta = curr_addr - sd.last_addr;
    if (sd.last_addr != 0) {
        sd.delta_history[sd.ptr] = delta;
        sd.ptr = (sd.ptr + 1) % STREAM_DELTA_HISTORY;
    }
    sd.last_addr = curr_addr;
    // Check if most recent deltas are monotonic (all same sign and nonzero)
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

// Helper: DIP set-dueling type for set
uint8_t get_dip_type(uint32_t set) {
    for (auto ls : dip_leader_sets) {
        if (set == ls) return DIP_LIP;
        if (set == ls + LLC_SETS / 2) return DIP_BIP;
    }
    return (psel >= DIP_PSEL_MAX / 2) ? DIP_LIP : DIP_BIP;
}

// Initialization
void InitReplacementState() {
    block_meta.resize(LLC_SETS * LLC_WAYS);
    ship_sig_table.resize(SHIP_SIG_ENTRIES);
    stream_detector.resize(LLC_SETS);

    dip_leader_sets.clear();
    for (uint16_t i = 0; i < DIP_LEADER_SETS; i++)
        dip_leader_sets.push_back(i * (LLC_SETS / DIP_LEADER_SETS));

    for (size_t i = 0; i < block_meta.size(); i++) {
        block_meta[i].rrpv = RRPV_MAX;
        block_meta[i].ship_sig = 0;
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

// Victim selection: RRIP
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Find block with RRPV_MAX
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

    // Streaming detection: if streaming, bypass fill
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
        return;
    }

    // On fill (miss)
    meta.ship_sig = sig;

    // Streaming phase: bypass fill (do not update RRPV, block is not inserted)
    if (streaming) {
        // In framework, block is inserted, so simulate bypass by setting RRPV=MAX (evict soon)
        meta.rrpv = RRPV_INSERT_LRU;
        streaming_bypass_fills++;
        return;
    }

    // SHiP strong reuse signature: insert at MRU
    if (ship_sig_table[sig].reuse_counter >= (SHIP_COUNTER_MAX - 1)) {
        meta.rrpv = RRPV_INSERT_MRU;
    }
    // DIP set-dueling: select LIP/BIP insertion depth
    else {
        uint8_t dip_type = get_dip_type(set);
        if (dip_type == DIP_LIP) {
            meta.rrpv = RRPV_INSERT_LRU;
        } else { // DIP_BIP
            // Insert at MRU most of the time, at LRU occasionally
            if ((rand() % DIP_BIP_PROB) == 0)
                meta.rrpv = RRPV_INSERT_LRU;
            else
                meta.rrpv = RRPV_INSERT_MRU;
        }
    }

    // Update SHiP reuse counter: on victim eviction
    uint32_t victim_way = GetVictimInSet(cpu, set, nullptr, PC, paddr, type);
    size_t victim_idx = get_block_meta_idx(set, victim_way);
    uint8_t victim_sig = block_meta[victim_idx].ship_sig;
    // If block was hit before eviction, increment reuse; else, decrement
    // Here, we use a basic approximation: if RRPV==0 before eviction, treat as reused
    if (block_meta[victim_idx].rrpv == RRPV_INSERT_MRU) {
        if (ship_sig_table[victim_sig].reuse_counter < SHIP_COUNTER_MAX)
            ship_sig_table[victim_sig].reuse_counter++;
    } else {
        if (ship_sig_table[victim_sig].reuse_counter > 0)
            ship_sig_table[victim_sig].reuse_counter--;
    }

    // DIP set-dueling: update PSEL on leader sets and hits
    for (auto ls : dip_leader_sets) {
        if (set == ls && hit && psel < DIP_PSEL_MAX) {
            psel++;
        }
        if (set == ls + LLC_SETS / 2 && hit && psel > 0) {
            psel--;
        }
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "PCSBDI: PC-Signature Streaming Bypass Dynamic Insertion stats\n";
    std::cout << "Total accesses: " << access_counter << "\n";
    std::cout << "Streaming fills bypassed: " << streaming_bypass_fills << "\n";
    size_t streaming_sets = 0;
    for (size_t i = 0; i < stream_detector.size(); i++) {
        if (is_streaming_set(i, stream_detector[i].last_addr)) streaming_sets++;
    }
    std::cout << "Streaming sets detected: " << streaming_sets << "\n";
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    std::cout << "PCSBDI heartbeat: accesses=" << access_counter
              << ", streaming_bypass_fills=" << streaming_bypass_fills << "\n";
}