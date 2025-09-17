#include <vector>
#include <cstdint>
#include <iostream>
#include <unordered_map>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

constexpr int SHIP_SIG_BITS = 12; // Signature bits (4096 entries)
constexpr int SHIP_MAX = 3;       // Saturating counter max
constexpr int FREQ_MAX = 7;       // Per-set frequency counter max

// --- Per-block SHiP signature ---
struct BlockMeta {
    uint16_t signature; // PC-derived signature
    uint8_t valid;
};

// --- Per-set state ---
struct SetState {
    std::vector<uint8_t> lru; // LRU stack (0: MRU, LLC_WAYS-1: LRU)
    std::vector<BlockMeta> meta;
    uint8_t freq_counter; // [0,7]: 0=streaming, 1-3=spatial, 4-7=temporal
    uint64_t last_addr;   // For stride detection
    int64_t last_stride;
};

std::vector<SetState> sets(LLC_SETS);

// --- Global SHiP signature table ---
std::vector<uint8_t> ship_table(1 << SHIP_SIG_BITS, 1); // 1: neutral start

// --- Global spatial locality detector ---
uint32_t spatial_hits = 0, spatial_total = 0;
bool spatial_phase = false;

// --- Initialize replacement state ---
void InitReplacementState() {
    for (auto& set : sets) {
        set.lru.assign(LLC_WAYS, 0);
        set.meta.assign(LLC_WAYS, {0, 0});
        set.freq_counter = 3;
        set.last_addr = 0;
        set.last_stride = 0;
    }
    ship_table.assign(ship_table.size(), 1);
    spatial_hits = 0;
    spatial_total = 0;
    spatial_phase = false;
}

// --- Find victim in set (LRU with SHiP boost) ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    SetState& s = sets[set];
    // Prefer invalid
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        if (!current_set[way].valid)
            return way;
    }
    // Find LRU, but boost blocks with high SHiP counter
    uint32_t victim = 0, min_lru = 0;
    uint8_t min_ship = SHIP_MAX+1;
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        uint16_t sig = s.meta[way].signature;
        uint8_t ship = ship_table[sig];
        if (ship < min_ship || (ship == min_ship && s.lru[way] > min_lru)) {
            min_ship = ship;
            min_lru = s.lru[way];
            victim = way;
        }
    }
    return victim;
}

// --- Update global spatial locality detector ---
void UpdateSpatialLocality(uint64_t set, uint64_t paddr) {
    SetState& s = sets[set];
    spatial_total++;
    int64_t stride = paddr - s.last_addr;
    if (s.last_addr && stride == s.last_stride && stride != 0) {
        spatial_hits++;
    }
    s.last_stride = stride;
    s.last_addr = paddr;
    if (spatial_total >= 2048) {
        spatial_phase = (spatial_hits * 100 / spatial_total) > 60;
        spatial_hits = 0;
        spatial_total = 0;
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
    SetState& s = sets[set];
    uint16_t sig = (PC ^ (PC >> 2)) & ((1 << SHIP_SIG_BITS) - 1);

    // Update spatial locality detector
    UpdateSpatialLocality(set, paddr);

    // Update per-set frequency counter
    if (hit) {
        if (s.freq_counter < FREQ_MAX) s.freq_counter++;
    } else {
        if (s.freq_counter > 0) s.freq_counter--;
    }

    // Update SHiP table
    if (hit) {
        if (ship_table[sig] < SHIP_MAX) ship_table[sig]++;
    } else {
        if (ship_table[sig] > 0) ship_table[sig]--;
    }

    // Determine insertion priority
    uint8_t lru_priority = LLC_WAYS - 1; // default: LRU
    if (ship_table[sig] >= 2) lru_priority = 0; // MRU if signature is hot
    else if (spatial_phase || s.freq_counter >= 4) lru_priority = 2; // spatial/temporal phase: mid
    else lru_priority = LLC_WAYS - 2; // streaming: near-LRU

    // Update LRU stack
    for (uint32_t i = 0; i < LLC_WAYS; i++) {
        if (i == way) s.lru[i] = lru_priority;
        else if (s.lru[i] <= lru_priority) s.lru[i]++;
    }
    // Clamp
    for (uint32_t i = 0; i < LLC_WAYS; i++)
        if (s.lru[i] > LLC_WAYS-1) s.lru[i] = LLC_WAYS-1;

    // Update block metadata
    s.meta[way].signature = sig;
    s.meta[way].valid = 1;
}

// --- Stats ---
uint64_t total_hits = 0, total_misses = 0, total_evictions = 0;
void PrintStats() {
    std::cout << "ASRFP: Hits=" << total_hits << " Misses=" << total_misses
              << " Evictions=" << total_evictions << std::endl;
}
void PrintStats_Heartbeat() {
    PrintStats();
}