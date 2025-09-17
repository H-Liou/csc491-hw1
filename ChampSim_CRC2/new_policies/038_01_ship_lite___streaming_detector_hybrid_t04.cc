#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// RRIP parameters
#define RRPV_BITS 2
#define RRPV_MAX 3

// SHiP-lite parameters
#define SHIP_SIG_BITS 6
#define SHIP_SIG_MASK ((1 << SHIP_SIG_BITS) - 1)
#define SHIP_TABLE_SIZE 4096 // 4K entries: 12-bit index

struct SHIPEntry {
    uint8_t reuse_counter; // 2 bits
};

std::vector<SHIPEntry> ship_table; // [SHIP_TABLE_SIZE]

// Per-block metadata
std::vector<uint8_t> block_rrpv;         // Per-block RRPV
std::vector<uint16_t> block_signature;   // Per-block SHiP signature

// Streaming detector per set
struct StreamSetState {
    uint64_t last_addr;
    int64_t last_delta;
    uint8_t stream_conf; // 2 bits: confidence of streaming
};
std::vector<StreamSetState> stream_state; // [LLC_SETS]

// Stats
uint64_t access_counter = 0;
uint64_t hits = 0;
uint64_t ship_mru_inserts = 0;
uint64_t ship_lru_inserts = 0;
uint64_t stream_bypass = 0;

// Helper: compute SHiP signature from PC
inline uint16_t get_ship_sig(uint64_t PC) {
    // CRC or simple hash; here: lower SHIP_SIG_BITS of PC
    return (PC >> 2) & SHIP_SIG_MASK;
}

// Initialization
void InitReplacementState() {
    block_rrpv.resize(LLC_SETS * LLC_WAYS, RRPV_MAX);
    block_signature.resize(LLC_SETS * LLC_WAYS, 0);
    ship_table.resize(SHIP_TABLE_SIZE);
    for (auto& e : ship_table) e.reuse_counter = 1; // neutral start
    stream_state.resize(LLC_SETS);
    for (auto& s : stream_state) {
        s.last_addr = 0;
        s.last_delta = 0;
        s.stream_conf = 0;
    }
    access_counter = 0;
    hits = 0;
    ship_mru_inserts = 0;
    ship_lru_inserts = 0;
    stream_bypass = 0;
}

// Find victim in the set
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Streaming bypass: if set is highly streaming, prefer block with RRPV_MAX
    if (stream_state[set].stream_conf >= 3) {
        for (uint32_t way = 0; way < LLC_WAYS; way++) {
            size_t idx = set * LLC_WAYS + way;
            if (block_rrpv[idx] == RRPV_MAX)
                return way;
        }
        // If none, increment all RRPVs and retry
        for (uint32_t way = 0; way < LLC_WAYS; way++) {
            size_t idx = set * LLC_WAYS + way;
            if (block_rrpv[idx] < RRPV_MAX)
                block_rrpv[idx]++;
        }
        for (uint32_t way = 0; way < LLC_WAYS; way++) {
            size_t idx = set * LLC_WAYS + way;
            if (block_rrpv[idx] == RRPV_MAX)
                return way;
        }
        // Fallback
        return 0;
    }

    // Normal RRIP victim selection
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        size_t idx = set * LLC_WAYS + way;
        if (block_rrpv[idx] == RRPV_MAX)
            return way;
    }
    // Increment all RRPVs and retry
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        size_t idx = set * LLC_WAYS + way;
        if (block_rrpv[idx] < RRPV_MAX)
            block_rrpv[idx]++;
    }
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        size_t idx = set * LLC_WAYS + way;
        if (block_rrpv[idx] == RRPV_MAX)
            return way;
    }
    // Fallback
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

    size_t idx = set * LLC_WAYS + way;

    // --- Streaming detector update ---
    int64_t cur_delta = (stream_state[set].last_addr == 0) ? 0 : (int64_t)paddr - (int64_t)stream_state[set].last_addr;
    if (cur_delta != 0 && cur_delta == stream_state[set].last_delta) {
        if (stream_state[set].stream_conf < 3) stream_state[set].stream_conf++;
    } else if (cur_delta != 0) {
        if (stream_state[set].stream_conf > 0) stream_state[set].stream_conf--;
    }
    stream_state[set].last_delta = cur_delta;
    stream_state[set].last_addr = paddr;

    // --- SHiP signature ---
    uint16_t sig = get_ship_sig(PC);
    block_signature[idx] = sig;
    SHIPEntry& ship_e = ship_table[sig];

    // --- On hit: promote to MRU, strengthen SHiP outcome ---
    if (hit) {
        hits++;
        block_rrpv[idx] = 0;
        if (ship_e.reuse_counter < 3) ship_e.reuse_counter++;
        return;
    }

    // --- Streaming bypass: if set is highly streaming, insert at distant RRPV or bypass ---
    if (stream_state[set].stream_conf >= 3) {
        block_rrpv[idx] = RRPV_MAX;
        stream_bypass++;
        return;
    }

    // --- SHiP insertion policy ---
    if (ship_e.reuse_counter >= 2) {
        block_rrpv[idx] = 0; // MRU
        ship_mru_inserts++;
    } else {
        block_rrpv[idx] = RRPV_MAX; // LRU
        ship_lru_inserts++;
    }

    // --- On miss: weaken SHiP outcome ---
    if (ship_e.reuse_counter > 0) ship_e.reuse_counter--;

    // No need for decay: SHiP counters are self-correcting
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "SHiP-Lite + Streaming Detector Hybrid Policy\n";
    std::cout << "Total accesses: " << access_counter << "\n";
    std::cout << "Hits: " << hits << "\n";
    std::cout << "SHiP MRU inserts: " << ship_mru_inserts << "\n";
    std::cout << "SHiP LRU inserts: " << ship_lru_inserts << "\n";
    std::cout << "Streaming bypass events: " << stream_bypass << "\n";
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    std::cout << "SHiP+Stream heartbeat: accesses=" << access_counter
              << ", hits=" << hits
              << ", MRU_inserts=" << ship_mru_inserts
              << ", LRU_inserts=" << ship_lru_inserts
              << ", stream_bypass=" << stream_bypass << "\n";
}