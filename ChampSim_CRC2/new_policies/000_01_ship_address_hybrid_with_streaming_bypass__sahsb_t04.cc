#include <vector>
#include <cstdint>
#include <cstring>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- Metadata structures ---
struct BLOCK_META {
    uint8_t rrpv;        // 2 bits: RRIP value
    uint8_t sig;         // 6 bits: SHiP-lite PC signature
    uint8_t outcome;     // 2 bits: SHiP-lite outcome counter
    uint8_t addr_reuse;  // 2 bits: address-based reuse counter
};

BLOCK_META repl_meta[LLC_SETS][LLC_WAYS];

// SHiP-lite signature table: 4096 entries x 2 bits = 8 KiB
#define SHIP_SIG_BITS 6
#define SHIP_SIG_ENTRIES (1 << SHIP_SIG_BITS)
uint8_t ship_outcome_table[SHIP_SIG_ENTRIES];

// Streaming detector: 2 bits/set + last_addr/set = 6 KiB
struct STREAM_META {
    uint8_t confidence; // 2 bits
    uint64_t last_addr;
    int64_t last_delta;
};
STREAM_META stream_meta[LLC_SETS];

// DRRIP set-dueling: 64 leader sets per policy, 10-bit PSEL
#define NUM_LEADER_SETS 64
#define PSEL_MAX 1023
uint16_t PSEL = PSEL_MAX / 2;
std::vector<uint32_t> leader_sets_srrip, leader_sets_brrip;

// Helper: map PC to SHiP signature
inline uint8_t get_signature(uint64_t PC) {
    return PC & (SHIP_SIG_ENTRIES - 1);
}

// Helper: map address to address reuse index (use lower 12 bits)
inline uint16_t get_addr_index(uint64_t addr) {
    return (addr >> 6) & 0xFFF; // 4K entries
}

// --- Initialization ---
void InitReplacementState() {
    memset(repl_meta, 0, sizeof(repl_meta));
    memset(ship_outcome_table, 0, sizeof(ship_outcome_table));
    memset(stream_meta, 0, sizeof(stream_meta));
    // Randomly select leader sets for SRRIP/BRRIP (no overlap)
    leader_sets_srrip.clear();
    leader_sets_brrip.clear();
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i) {
        leader_sets_srrip.push_back(i);
        leader_sets_brrip.push_back(i + NUM_LEADER_SETS);
    }
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
    // Streaming bypass: if detected, always choose invalid block or way 0
    if (stream_meta[set].confidence == 3) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (!current_set[way].valid)
                return way;
        return 0;
    }
    // RRIP: choose block with RRPV==3, else increment RRPV and retry
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (repl_meta[set][way].rrpv == 3)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (repl_meta[set][way].rrpv < 3)
                repl_meta[set][way].rrpv++;
    }
}

// --- Replacement state update ---
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
    // Streaming detector update
    uint64_t last_addr = stream_meta[set].last_addr;
    int64_t delta = (last_addr) ? (int64_t)(paddr - last_addr) : 0;
    if (last_addr) {
        if (delta == stream_meta[set].last_delta && delta != 0) {
            if (stream_meta[set].confidence < 3)
                stream_meta[set].confidence++;
        } else {
            if (stream_meta[set].confidence > 0)
                stream_meta[set].confidence--;
        }
    }
    stream_meta[set].last_addr = paddr;
    stream_meta[set].last_delta = delta;

    // SHiP signature and address reuse
    uint8_t sig = get_signature(PC);
    uint8_t &outcome = ship_outcome_table[sig];
    uint8_t &addr_reuse = repl_meta[set][way].addr_reuse;

    // On hit: increment outcome and addr_reuse
    if (hit) {
        if (outcome < 3) outcome++;
        if (addr_reuse < 3) addr_reuse++;
        repl_meta[set][way].rrpv = 0; // protect reused block
    } else {
        // On miss/eviction: decay outcome and addr_reuse
        if (outcome > 0) outcome--;
        if (addr_reuse > 0) addr_reuse--;
    }

    // On fill: set signature, outcome, and reuse
    if (!hit) {
        repl_meta[set][way].sig = sig;
        repl_meta[set][way].outcome = outcome;
        // Address reuse: initialize from previous victim (if any)
        repl_meta[set][way].addr_reuse = addr_reuse;
        // DRRIP set-dueling: pick insertion depth
        bool is_leader_srrip = std::find(leader_sets_srrip.begin(), leader_sets_srrip.end(), set) != leader_sets_srrip.end();
        bool is_leader_brrip = std::find(leader_sets_brrip.begin(), leader_sets_brrip.end(), set) != leader_sets_brrip.end();
        uint8_t ins_rrpv = 2; // default SRRIP
        if (is_leader_brrip || (!is_leader_srrip && PSEL < PSEL_MAX / 2))
            ins_rrpv = (rand() % 32 == 0) ? 2 : 3; // BRRIP: mostly distant
        // Streaming: if confidence==3, insert with RRPV=3 (bypass)
        if (stream_meta[set].confidence == 3)
            ins_rrpv = 3;
        // SHiP signature: if outcome low, insert distant
        if (outcome < 2)
            ins_rrpv = 3;
        // Address reuse: if addr_reuse low, insert distant
        if (addr_reuse < 2)
            ins_rrpv = 3;
        repl_meta[set][way].rrpv = ins_rrpv;
        // Update PSEL for set-dueling
        if (is_leader_srrip && hit)
            if (PSEL < PSEL_MAX) PSEL++;
        if (is_leader_brrip && hit)
            if (PSEL > 0) PSEL--;
    }
}

// --- Stats ---
void PrintStats() {
    // (Optional) Print SHiP outcome histogram, streaming detector stats, etc.
    std::cout << "SHiP-Address Hybrid Streaming Bypass stats\n";
}

void PrintStats_Heartbeat() {
    // (Optional) Print periodic stats
}