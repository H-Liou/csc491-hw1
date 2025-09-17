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
#define RRPV_INSERT_LONG (RRPV_MAX - 1)
#define RRPV_INSERT_DISTANT (RRPV_MAX)
#define RRPV_INSERT_MRU 0

// SHiP-lite constants
#define SHIP_SIG_BITS 6
#define SHIP_SIG_ENTRIES (1 << SHIP_SIG_BITS)
#define SHIP_COUNTER_BITS 2
#define SHIP_COUNTER_MAX ((1 << SHIP_COUNTER_BITS) - 1)

// Dead-block counter
#define DEAD_BITS 2
#define DEAD_MAX ((1 << DEAD_BITS) - 1)
#define DEAD_DECAY_EPOCH 2048 // Decay every 2048 accesses

// Streaming detector
#define STREAM_DELTA_HISTORY 4
#define STREAM_DELTA_THRESHOLD 3 // 3/4 monotonic deltas triggers streaming

// Set-dueling
#define DUEL_LEADER_SETS 64
#define DUEL_PSEL_BITS 10
#define DUEL_PSEL_MAX ((1 << DUEL_PSEL_BITS) - 1)
#define DUEL_SRRIP 0
#define DUEL_BRRIP 1

struct LLC_BLOCK_META {
    uint8_t rrpv;            // 2 bits
    uint8_t dead_counter;    // 2 bits
    uint8_t ship_sig;        // 6 bits
};

struct SHIP_SIG_ENTRY {
    uint8_t reuse_counter;   // 2 bits
};

struct STREAM_DETECTOR {
    uint64_t last_addr;
    int64_t delta_history[STREAM_DELTA_HISTORY];
    uint8_t ptr;
};

std::vector<LLC_BLOCK_META> block_meta;
std::vector<SHIP_SIG_ENTRY> ship_sig_table;
std::vector<STREAM_DETECTOR> stream_detector;
std::vector<uint8_t> set_duel_type; // 0:SRRIP, 1:BRRIP
uint16_t psel = DUEL_PSEL_MAX / 2;

uint64_t access_counter = 0;

// Assign leader sets for set-dueling
std::vector<uint16_t> leader_sets;

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

// Helper: set-dueling type for set
uint8_t get_duel_type(uint32_t set) {
    for (auto ls : leader_sets) {
        if (set == ls) return DUEL_SRRIP;
        if (set == ls + LLC_SETS / 2) return DUEL_BRRIP;
    }
    return (psel >= DUEL_PSEL_MAX / 2) ? DUEL_SRRIP : DUEL_BRRIP;
}

// Initialization
void InitReplacementState() {
    block_meta.resize(LLC_SETS * LLC_WAYS);
    ship_sig_table.resize(SHIP_SIG_ENTRIES);
    stream_detector.resize(LLC_SETS);
    set_duel_type.resize(LLC_SETS, 0);

    // Randomly assign leader sets for set-dueling
    leader_sets.clear();
    for (uint16_t i = 0; i < DUEL_LEADER_SETS; i++)
        leader_sets.push_back(i * (LLC_SETS / DUEL_LEADER_SETS));

    // Initialize structures
    for (size_t i = 0; i < block_meta.size(); i++) {
        block_meta[i].rrpv = RRPV_MAX;
        block_meta[i].dead_counter = 0;
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
    // Should not happen
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

    // Dead-block decay periodically
    if (access_counter % DEAD_DECAY_EPOCH == 0) {
        for (size_t i = 0; i < block_meta.size(); i++) {
            if (block_meta[i].dead_counter > 0)
                block_meta[i].dead_counter--;
        }
    }

    // On cache hit
    if (hit) {
        // Update SHiP reuse counter
        if (ship_sig_table[sig].reuse_counter < SHIP_COUNTER_MAX)
            ship_sig_table[sig].reuse_counter++;
        // Update dead-block counter
        if (meta.dead_counter < DEAD_MAX)
            meta.dead_counter++;
        // Promote to MRU
        meta.rrpv = RRPV_INSERT_MRU;
        return;
    }

    // On fill (miss)
    meta.ship_sig = sig;
    // Streaming block: insert at distant RRPV or bypass
    if (streaming) {
        meta.rrpv = RRPV_INSERT_DISTANT;
        meta.dead_counter = DEAD_MAX; // streaming likely dead
        // Optionally: bypass fill (not inserting block) -- but template expects fill
        // So just insert at distant RRPV
    }
    // Dead-block: insert at distant RRPV
    else if (meta.dead_counter == DEAD_MAX) {
        meta.rrpv = RRPV_INSERT_DISTANT;
    }
    // SHiP signature with strong reuse: insert at MRU
    else if (ship_sig_table[sig].reuse_counter >= (SHIP_COUNTER_MAX - 1)) {
        meta.rrpv = RRPV_INSERT_MRU;
        meta.dead_counter = 0;
    }
    // Set-dueling: SRRIP vs BRRIP
    else {
        uint8_t duel = get_duel_type(set);
        if (duel == DUEL_SRRIP)
            meta.rrpv = RRPV_INSERT_LONG;
        else // BRRIP
            meta.rrpv = (rand() % 32 == 0) ? RRPV_INSERT_LONG : RRPV_INSERT_DISTANT;
    }
    // Reset dead-block counter on fill
    meta.dead_counter = 0;

    // Update SHiP reuse counter: on eviction
    // Find victim block's SHiP signature
    uint32_t victim_way = GetVictimInSet(cpu, set, nullptr, PC, paddr, type);
    size_t victim_idx = get_block_meta_idx(set, victim_way);
    uint8_t victim_sig = block_meta[victim_idx].ship_sig;
    if (block_meta[victim_idx].dead_counter == 0) {
        // If block was reused, increment SHiP counter
        if (ship_sig_table[victim_sig].reuse_counter < SHIP_COUNTER_MAX)
            ship_sig_table[victim_sig].reuse_counter++;
    } else {
        // If not reused, decrement SHiP counter
        if (ship_sig_table[victim_sig].reuse_counter > 0)
            ship_sig_table[victim_sig].reuse_counter--;
    }

    // Set-dueling PSEL update
    for (auto ls : leader_sets) {
        if (set == ls) {
            // SRRIP leader: if hit, increment PSEL
            if (hit && psel < DUEL_PSEL_MAX) psel++;
        }
        if (set == ls + LLC_SETS / 2) {
            // BRRIP leader: if hit, decrement PSEL
            if (hit && psel > 0) psel--;
        }
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "SASDH: SHiP-Address Streaming DeadBlock Hybrid policy stats\n";
    // Optionally print SHiP table, dead-block histogram, streaming set count
    size_t streaming_sets = 0;
    for (size_t i = 0; i < stream_detector.size(); i++) {
        if (is_streaming_set(i, stream_detector[i].last_addr)) streaming_sets++;
    }
    std::cout << "Streaming sets detected: " << streaming_sets << "\n";
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Optionally print access count
    std::cout << "SASDH heartbeat: accesses=" << access_counter << "\n";
}