#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// SHiP-lite: 6-bit signature per block, 2-bit outcome counter per signature
#define SIG_BITS 6
#define SIG_MASK ((1 << SIG_BITS) - 1)
#define SIG_TABLE_SIZE (1 << SIG_BITS)
struct BlockMeta {
    uint8_t rrpv;      // 2 bits
    uint8_t signature; // 6 bits
};
BlockMeta meta[LLC_SETS][LLC_WAYS];
uint8_t outcome_table[SIG_TABLE_SIZE]; // 2 bits per entry

// Streaming detector: last address, last delta, 2-bit confidence per set
struct StreamDetect {
    uint64_t last_addr;
    int64_t last_delta;
    uint8_t stream_conf; // 2 bits
};
StreamDetect stream_meta[LLC_SETS];

// DIP set-dueling: 64 leader sets for LIP, 64 for BIP
#define NUM_LEADER_SETS 64
std::vector<uint32_t> leader_lip;
std::vector<uint32_t> leader_bip;

// PSEL: 10-bit global selector
uint16_t PSEL = 512;

// Helper: assign leader sets deterministically
void InitLeaderSets() {
    leader_lip.clear();
    leader_bip.clear();
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i) {
        leader_lip.push_back(i);
        leader_bip.push_back(i + LLC_SETS/2);
    }
}

// Streaming detector: returns true if stream detected in this set
inline bool IsStreaming(uint32_t set, uint64_t paddr) {
    StreamDetect &sd = stream_meta[set];
    int64_t delta = paddr - sd.last_addr;
    bool is_stream = false;
    if (sd.last_addr != 0) {
        if (delta == sd.last_delta && delta != 0) {
            if (sd.stream_conf < 3) sd.stream_conf++;
        } else {
            if (sd.stream_conf > 0) sd.stream_conf--;
        }
        if (sd.stream_conf >= 2) is_stream = true;
    }
    sd.last_delta = delta;
    sd.last_addr = paddr;
    return is_stream;
}

// Initialize replacement state
void InitReplacementState() {
    memset(meta, 0, sizeof(meta));
    memset(stream_meta, 0, sizeof(stream_meta));
    memset(outcome_table, 1, sizeof(outcome_table)); // weakly dead by default
    InitLeaderSets();
    PSEL = 512;
}

// Find victim in the set (prefer invalid, else RRPV==3)
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (!current_set[way].valid)
            return way;
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (meta[set][way].rrpv == 3)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (meta[set][way].rrpv < 3)
                meta[set][way].rrpv++;
    }
    return 0; // Should not reach
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
    // --- Streaming detector ---
    bool is_stream = IsStreaming(set, paddr);

    // --- SHiP signature ---
    uint8_t sig = (PC ^ (paddr >> 5)) & SIG_MASK;
    meta[set][way].signature = sig;

    // --- DIP set-dueling: choose insertion policy ---
    bool is_leader_lip = false, is_leader_bip = false;
    for (auto s : leader_lip) if (set == s) is_leader_lip = true;
    for (auto s : leader_bip) if (set == s) is_leader_bip = true;

    uint8_t ins_rrpv = 3; // default distant

    if (is_stream) {
        // Streaming: bypass (do not insert) if possible, else insert at distant
        ins_rrpv = 3;
    } else {
        // SHiP: use outcome table to bias insertion
        if (outcome_table[sig] >= 2)
            ins_rrpv = 2; // recently reused, insert at RRPV=2
        else
            ins_rrpv = 3; // dead, insert at distant

        // DIP set-dueling overrides for leader sets
        if (is_leader_lip)
            ins_rrpv = 3; // LIP: always distant
        else if (is_leader_bip)
            ins_rrpv = (rand() % 32 == 0) ? 2 : 3; // BIP: mostly distant, 1/32 at RRPV=2

        // Normal sets: pick policy based on PSEL
        else if (!is_leader_lip && !is_leader_bip) {
            if (PSEL >= 512)
                ins_rrpv = 3; // LIP
            else
                ins_rrpv = (rand() % 32 == 0) ? 2 : 3; // BIP
        }
    }

    // --- On hit: promote to MRU, update outcome table ---
    if (hit) {
        meta[set][way].rrpv = 0;
        if (outcome_table[sig] < 3) outcome_table[sig]++;
        // Update PSEL for leader sets
        if (is_leader_lip && PSEL < 1023) PSEL++;
        if (is_leader_bip && PSEL > 0) PSEL--;
        return;
    }

    // --- On miss/fill: set insertion RRPV, update outcome table for victim ---
    meta[set][way].rrpv = ins_rrpv;
    // Victim block's signature: decrement outcome if not reused
    uint8_t victim_sig = meta[set][way].signature;
    if (outcome_table[victim_sig] > 0) outcome_table[victim_sig]--;
}

// Print end-of-simulation statistics
void PrintStats() {
    uint32_t stream_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (stream_meta[s].stream_conf >= 2) stream_sets++;
    uint32_t reused = 0;
    for (uint32_t i = 0; i < SIG_TABLE_SIZE; ++i)
        if (outcome_table[i] >= 2) reused++;
    std::cout << "SHiP-Stream-DIP: streaming sets=" << stream_sets << "/" << LLC_SETS
              << ", reused sigs=" << reused << "/" << SIG_TABLE_SIZE
              << ", PSEL=" << PSEL << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // No periodic decay needed
}