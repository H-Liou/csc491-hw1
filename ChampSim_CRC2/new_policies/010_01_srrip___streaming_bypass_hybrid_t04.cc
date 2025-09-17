#include <vector>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// SRRIP/BRRIP set-dueling: 32 leader sets, 10-bit PSEL
#define NUM_LEADER_SETS 32
#define PSEL_BITS 10
uint16_t psel = (1 << (PSEL_BITS - 1));
std::vector<uint8_t> leader_set_type; // 0:SRRIP, 1:BRRIP

// Per-block metadata: 2-bit RRPV
std::vector<uint8_t> block_rrpv;

// Streaming detector: per-set 2-bit saturating counter
std::vector<uint8_t> stream_cnt;
std::vector<uint64_t> last_addr;

// Stats
uint64_t access_counter = 0;
uint64_t hits = 0;
uint64_t srrip_inserts = 0;
uint64_t brrip_inserts = 0;
uint64_t stream_bypass = 0;

// Helper: get block meta index
inline size_t get_block_idx(uint32_t set, uint32_t way) {
    return set * LLC_WAYS + way;
}

// Initialization
void InitReplacementState() {
    block_rrpv.resize(LLC_SETS * LLC_WAYS, 3); // LRU
    leader_set_type.resize(NUM_LEADER_SETS);
    stream_cnt.resize(LLC_SETS, 0);
    last_addr.resize(LLC_SETS, 0);

    // Assign leader sets: evenly spaced
    for (size_t i = 0; i < NUM_LEADER_SETS; i++)
        leader_set_type[i] = (i < NUM_LEADER_SETS / 2) ? 0 : 1; // 0:SRRIP, 1:BRRIP

    access_counter = 0;
    hits = 0;
    srrip_inserts = 0;
    brrip_inserts = 0;
    stream_bypass = 0;
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
        size_t idx = get_block_idx(set, way);
        if (block_rrpv[idx] == 3)
            return way;
    }
    // If none, increment RRPVs and retry
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        size_t idx = get_block_idx(set, way);
        if (block_rrpv[idx] < 3)
            block_rrpv[idx]++;
    }
    // Second pass
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        size_t idx = get_block_idx(set, way);
        if (block_rrpv[idx] == 3)
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

    // --- Streaming detector ---
    uint64_t addr = paddr >> 6; // block address
    uint64_t delta = (last_addr[set] == 0) ? 0 : (addr > last_addr[set] ? addr - last_addr[set] : last_addr[set] - addr);
    if (last_addr[set] != 0) {
        if (delta == 1 || delta == 0) {
            if (stream_cnt[set] < 3) stream_cnt[set]++;
        } else {
            if (stream_cnt[set] > 0) stream_cnt[set]--;
        }
    }
    last_addr[set] = addr;

    size_t idx = get_block_idx(set, way);

    // On hit: promote block to MRU
    if (hit) {
        block_rrpv[idx] = 0;
        hits++;
        return;
    }

    // --- Streaming bypass/insertion ---
    // If streaming detected, bypass (do not insert) with high stream_cnt
    if (stream_cnt[set] == 3) {
        // Simulate bypass by inserting at RRPV=3 (distant LRU)
        block_rrpv[idx] = 3;
        stream_bypass++;
        return;
    }

    // --- SRRIP/BRRIP set-dueling ---
    bool is_leader = (set % (LLC_SETS / NUM_LEADER_SETS)) == 0;
    uint8_t leader_type = 0;
    if (is_leader) {
        leader_type = leader_set_type[set / (LLC_SETS / NUM_LEADER_SETS)];
    }
    bool use_brrip = false;
    if (is_leader) {
        use_brrip = (leader_type == 1);
    } else {
        use_brrip = (psel < (1 << (PSEL_BITS - 1)));
    }

    // SRRIP: insert at RRPV=2 (distant but not LRU)
    // BRRIP: insert at RRPV=2 with low probability, else RRPV=0 (MRU)
    if (use_brrip) {
        // BRRIP: insert at RRPV=2 with 1/32 probability, else RRPV=0
        if ((access_counter & 0x1F) == 0) {
            block_rrpv[idx] = 2;
        } else {
            block_rrpv[idx] = 0;
        }
        brrip_inserts++;
    } else {
        block_rrpv[idx] = 2;
        srrip_inserts++;
    }

    // --- DIP PSEL update: only for leader sets ---
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
    std::cout << "SRRIP + Streaming Bypass Hybrid\n";
    std::cout << "Total accesses: " << access_counter << "\n";
    std::cout << "Hits: " << hits << "\n";
    std::cout << "SRRIP inserts: " << srrip_inserts << "\n";
    std::cout << "BRRIP inserts: " << brrip_inserts << "\n";
    std::cout << "Streaming bypasses: " << stream_bypass << "\n";
    std::cout << "PSEL value: " << psel << "\n";
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    std::cout << "SRRIP+Streaming heartbeat: accesses=" << access_counter
              << ", hits=" << hits
              << ", srrip=" << srrip_inserts
              << ", brrip=" << brrip_inserts
              << ", stream_bypass=" << stream_bypass
              << ", PSEL=" << psel << "\n";
}