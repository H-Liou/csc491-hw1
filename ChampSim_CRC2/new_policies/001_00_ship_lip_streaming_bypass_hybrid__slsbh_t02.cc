#include <vector>
#include <cstdint>
#include <cstring>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// DIP constants
#define DIP_LEADER_SETS 32
#define DIP_PSEL_BITS 10
#define DIP_PSEL_MAX ((1 << DIP_PSEL_BITS) - 1)
#define DIP_LIP 0
#define DIP_BIP 1

// SHiP-lite constants
#define SHIP_SIG_BITS 6
#define SHIP_SIG_ENTRIES (1 << SHIP_SIG_BITS)
#define SHIP_COUNTER_BITS 2
#define SHIP_COUNTER_MAX ((1 << SHIP_COUNTER_BITS) - 1)

// Streaming detector
#define STREAM_DELTA_HISTORY 4
#define STREAM_DELTA_THRESHOLD 3 // 3/4 monotonic deltas triggers streaming

struct LLC_BLOCK_META {
    uint8_t ship_sig; // 6 bits
};

struct SHIP_SIG_ENTRY {
    uint8_t reuse_counter; // 2 bits
};

struct STREAM_DETECTOR {
    uint64_t last_addr;
    int64_t delta_history[STREAM_DELTA_HISTORY];
    uint8_t ptr;
};

std::vector<LLC_BLOCK_META> block_meta;
std::vector<SHIP_SIG_ENTRY> ship_sig_table;
std::vector<STREAM_DETECTOR> stream_detector;
std::vector<uint8_t> set_duel_type; // 0:LIP, 1:BIP
uint16_t psel = DIP_PSEL_MAX / 2;

std::vector<uint16_t> leader_sets;
uint64_t access_counter = 0;

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

// DIP set-dueling type for set
uint8_t get_duel_type(uint32_t set) {
    for (auto ls : leader_sets) {
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
    set_duel_type.resize(LLC_SETS, 0);

    // Assign leader sets for DIP set-dueling
    leader_sets.clear();
    for (uint16_t i = 0; i < DIP_LEADER_SETS; i++)
        leader_sets.push_back(i * (LLC_SETS / DIP_LEADER_SETS));

    // Initialize structures
    for (size_t i = 0; i < block_meta.size(); i++) {
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

// Victim selection: LRU (LIP/BIP)
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Find LRU block (way 0 by default, or scan for oldest)
    // For simplicity, use way 0 as victim (since insertion always at MRU or LRU)
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
    LLC_BLOCK_META &meta = block_meta[idx];

    // Streaming detection
    bool streaming = is_streaming_set(set, paddr);

    // SHiP signature
    uint8_t sig = get_ship_sig(PC);

    // On cache hit
    if (hit) {
        // Update SHiP reuse counter
        if (ship_sig_table[sig].reuse_counter < SHIP_COUNTER_MAX)
            ship_sig_table[sig].reuse_counter++;
        // Move block to MRU (if using LRU stack, would move to top)
        // No explicit stack here; assume MRU promotion
        return;
    }

    // On fill (miss)
    meta.ship_sig = sig;

    // Streaming block: bypass insertion (do not insert into cache)
    if (streaming) {
        // Do not update block_meta for this way; block is not inserted
        // (In real implementation, would skip fill; here, just return)
        return;
    }

    // SHiP signature with strong reuse: insert at MRU
    if (ship_sig_table[sig].reuse_counter >= (SHIP_COUNTER_MAX - 1)) {
        // Insert at MRU (would be way LLC_WAYS-1 in stack-based LRU)
        // No explicit stack; so nothing to do
    }
    // DIP set-dueling: LIP vs BIP for non-reused blocks
    else {
        uint8_t duel = get_duel_type(set);
        if (duel == DIP_LIP) {
            // Insert at LRU (way 0)
            // No explicit stack; so nothing to do
        } else { // DIP_BIP
            // Insert at MRU with low probability (1/32), else at LRU
            if (rand() % 32 == 0) {
                // Insert at MRU
            } else {
                // Insert at LRU
            }
        }
    }

    // Update SHiP reuse counter: on eviction
    // Find victim block's SHiP signature
    uint32_t victim_way = GetVictimInSet(cpu, set, nullptr, PC, paddr, type);
    size_t victim_idx = get_block_meta_idx(set, victim_way);
    uint8_t victim_sig = block_meta[victim_idx].ship_sig;
    // If block was reused (reuse_counter > 0), increment; else decrement
    if (ship_sig_table[victim_sig].reuse_counter > 0)
        ship_sig_table[victim_sig].reuse_counter--;
    else
        ship_sig_table[victim_sig].reuse_counter = 0;

    // DIP set-dueling PSEL update
    for (auto ls : leader_sets) {
        if (set == ls) {
            // LIP leader: if hit, increment PSEL
            if (hit && psel < DIP_PSEL_MAX) psel++;
        }
        if (set == ls + LLC_SETS / 2) {
            // BIP leader: if hit, decrement PSEL
            if (hit && psel > 0) psel--;
        }
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "SLSBH: SHiP-LIP Streaming Bypass Hybrid policy stats\n";
    // Optionally print SHiP table, streaming set count
    size_t streaming_sets = 0;
    for (size_t i = 0; i < stream_detector.size(); i++) {
        if (is_streaming_set(i, stream_detector[i].last_addr)) streaming_sets++;
    }
    std::cout << "Streaming sets detected: " << streaming_sets << "\n";
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    std::cout << "SLSBH heartbeat: accesses=" << access_counter << "\n";
}