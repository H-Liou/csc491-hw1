#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// DRRIP set-dueling: 32 leader sets, 10-bit PSEL
#define NUM_LEADER_SETS 32
#define PSEL_BITS 10
uint16_t psel = (1 << (PSEL_BITS - 1));
std::vector<uint8_t> leader_set_type; // 0:SRRIP, 1:BRRIP

// Per-block metadata: 2-bit RRPV
struct BLOCK_META {
    uint8_t rrpv; // 2 bits
};
std::vector<BLOCK_META> block_meta;

// SHiP-lite: 1024-entry signature table, 6-bit signatures, 2-bit outcome counters
#define SHIP_SIG_BITS 6
#define SHIP_TABLE_SIZE 1024
struct SHIP_ENTRY {
    uint8_t counter; // 2 bits
};
std::vector<SHIP_ENTRY> ship_table;

// Streaming detector: per-set, 8-bit delta history, 2-bit streaming counter
struct STREAM_DETECT {
    uint64_t last_addr;
    uint8_t delta_hist; // 8 bits: last 8 deltas (1 if monotonic, 0 otherwise)
    uint8_t stream_cnt; // 2 bits
};
std::vector<STREAM_DETECT> stream_detect;

// Stats
uint64_t access_counter = 0;
uint64_t ship_mru_inserts = 0;
uint64_t ship_lru_inserts = 0;
uint64_t stream_bypass = 0;
uint64_t hits = 0;
uint64_t srip_inserts = 0;
uint64_t brip_inserts = 0;

// Helper: get block meta index
inline size_t get_block_meta_idx(uint32_t set, uint32_t way) {
    return set * LLC_WAYS + way;
}

// Helper: SHiP signature (6 bits from PC)
inline uint16_t get_ship_sig(uint64_t PC) {
    return (PC ^ (PC >> 6)) & ((1 << SHIP_SIG_BITS) - 1);
}

// Helper: SHiP table index
inline size_t get_ship_idx(uint16_t sig) {
    return sig % SHIP_TABLE_SIZE;
}

// Initialization
void InitReplacementState() {
    block_meta.resize(LLC_SETS * LLC_WAYS);
    leader_set_type.resize(NUM_LEADER_SETS);
    ship_table.resize(SHIP_TABLE_SIZE);
    stream_detect.resize(LLC_SETS);

    // Assign leader sets: evenly spaced
    for (size_t i = 0; i < NUM_LEADER_SETS; i++) {
        leader_set_type[i] = (i < NUM_LEADER_SETS / 2) ? 0 : 1; // 0:SRRIP, 1:BRRIP
    }

    for (size_t i = 0; i < block_meta.size(); i++) {
        block_meta[i].rrpv = 3; // LRU
    }
    for (size_t i = 0; i < ship_table.size(); i++) {
        ship_table[i].counter = 1; // neutral
    }
    for (size_t i = 0; i < stream_detect.size(); i++) {
        stream_detect[i].last_addr = 0;
        stream_detect[i].delta_hist = 0;
        stream_detect[i].stream_cnt = 0;
    }

    access_counter = 0;
    ship_mru_inserts = 0;
    ship_lru_inserts = 0;
    stream_bypass = 0;
    hits = 0;
    srip_inserts = 0;
    brip_inserts = 0;
}

// Victim selection: standard RRIP
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Find block with RRPV==3
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        size_t idx = get_block_meta_idx(set, way);
        if (block_meta[idx].rrpv == 3)
            return way;
    }
    // If none, increment RRPVs and retry
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        size_t idx = get_block_meta_idx(set, way);
        if (block_meta[idx].rrpv < 3)
            block_meta[idx].rrpv++;
    }
    // Second pass
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        size_t idx = get_block_meta_idx(set, way);
        if (block_meta[idx].rrpv == 3)
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

    // --- Streaming detector update ---
    STREAM_DETECT &sd = stream_detect[set];
    uint64_t delta = (sd.last_addr == 0) ? 0 : (paddr > sd.last_addr ? paddr - sd.last_addr : sd.last_addr - paddr);
    bool monotonic = (delta < 256 && delta != 0); // small, nonzero deltas
    sd.delta_hist = ((sd.delta_hist << 1) | (monotonic ? 1 : 0)) & 0xFF;
    // If last 6/8 deltas are monotonic, streaming phase
    uint8_t monotonic_count = 0;
    for (int i = 0; i < 8; i++) if (sd.delta_hist & (1 << i)) monotonic_count++;
    if (monotonic_count >= 6) {
        if (sd.stream_cnt < 3) sd.stream_cnt++;
    } else {
        if (sd.stream_cnt > 0) sd.stream_cnt--;
    }
    sd.last_addr = paddr;

    // --- SHiP-lite update ---
    uint16_t sig = get_ship_sig(PC);
    size_t ship_idx = get_ship_idx(sig);
    SHIP_ENTRY &ship_entry = ship_table[ship_idx];

    // On hit: promote block to MRU, increment SHiP counter (max saturate)
    if (hit) {
        meta.rrpv = 0;
        if (ship_entry.counter < 3) ship_entry.counter++;
        hits++;
        return;
    }

    // On miss: insertion
    // DRRIP set-dueling: leader sets use fixed policy, others use PSEL
    bool is_leader = (set % (LLC_SETS / NUM_LEADER_SETS)) == 0;
    uint8_t leader_type = 0;
    if (is_leader) {
        leader_type = leader_set_type[set / (LLC_SETS / NUM_LEADER_SETS)];
    }
    bool use_brip = false;
    if (is_leader) {
        use_brip = (leader_type == 1);
    } else {
        use_brip = (psel < (1 << (PSEL_BITS - 1)));
    }

    // --- Streaming bypass logic ---
    bool streaming = (sd.stream_cnt >= 2);
    bool bypass = false;
    if (streaming && ((access_counter & 0xF) == 0)) { // 1/16 probability
        bypass = true;
        stream_bypass++;
    }

    // --- SHiP-lite insertion control ---
    if (bypass) {
        // Insert at distant RRPV (3), simulating bypass
        meta.rrpv = 3;
        ship_lru_inserts++;
        // No SHiP update for bypassed blocks
    } else if (ship_entry.counter >= 2) {
        // High reuse signature: insert at MRU
        meta.rrpv = 0;
        ship_mru_inserts++;
    } else {
        // Low reuse signature: insert at LRU
        meta.rrpv = 3;
        ship_lru_inserts++;
    }

    // DRRIP: adjust insertion for non-SHiP blocks (if not streaming)
    if (!bypass && ship_entry.counter == 1) {
        if (use_brip) {
            if ((access_counter & 0x1F) == 0) // 1/32
                meta.rrpv = 0;
            else
                meta.rrpv = 3;
            brip_inserts++;
        } else {
            meta.rrpv = 2; // SRRIP default
            srip_inserts++;
        }
    }

    // On victim: update SHiP counter (if not streaming bypass)
    if (!bypass) {
        size_t victim_sig = get_ship_sig(PC);
        size_t victim_idx = get_ship_idx(victim_sig);
        SHIP_ENTRY &victim_entry = ship_table[victim_idx];
        if (victim_entry.counter > 0) victim_entry.counter--;
    }

    // DRRIP PSEL update: only for leader sets
    if (is_leader && !hit) {
        if (leader_type == 0) { // SRRIP leader
            if (psel < ((1 << PSEL_BITS) - 1)) psel++;
        } else { // BRRIP leader
            if (psel > 0) psel--;
        }
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "SHiP-Lite + Streaming Bypass DRRIP Hybrid\n";
    std::cout << "Total accesses: " << access_counter << "\n";
    std::cout << "Hits: " << hits << "\n";
    std::cout << "SHiP MRU inserts: " << ship_mru_inserts << "\n";
    std::cout << "SHiP LRU inserts: " << ship_lru_inserts << "\n";
    std::cout << "Streaming bypasses: " << stream_bypass << "\n";
    std::cout << "SRRIP inserts: " << srip_inserts << "\n";
    std::cout << "BRRIP inserts: " << brip_inserts << "\n";
    std::cout << "PSEL value: " << psel << "\n";
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    std::cout << "SHiP-Lite+Streaming heartbeat: accesses=" << access_counter
              << ", hits=" << hits
              << ", ship_mru=" << ship_mru_inserts
              << ", ship_lru=" << ship_lru_inserts
              << ", stream_bypass=" << stream_bypass
              << ", srip=" << srip_inserts
              << ", brip=" << brip_inserts
              << ", PSEL=" << psel << "\n";
}