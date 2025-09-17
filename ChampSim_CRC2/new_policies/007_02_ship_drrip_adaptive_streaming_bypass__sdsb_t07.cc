#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- DRRIP: 2-bit RRPV ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// --- DRRIP set-dueling: 64 leader sets (32 SRRIP, 32 BRRIP), 10-bit PSEL ---
#define NUM_LEADER_SETS 64
#define PSEL_BITS 10
uint16_t PSEL = 1 << (PSEL_BITS - 1); // 10-bit saturating counter, init mid
std::vector<uint32_t> leader_sets_sr;
std::vector<uint32_t> leader_sets_br;

// --- SHiP-lite: 5-bit PC signature, 2-bit outcome table (32 entries) ---
#define SHIP_SIG_BITS 5
#define SHIP_TABLE_SIZE (1 << SHIP_SIG_BITS)
uint8_t ship_signature[LLC_SETS][LLC_WAYS];
uint8_t ship_table[SHIP_TABLE_SIZE];

// --- Streaming detector: per-set, 2-entry delta history, 2-bit streaming counter ---
uint64_t last_addr[LLC_SETS];
int64_t last_delta[LLC_SETS];
uint8_t stream_ctr[LLC_SETS]; // 2 bits per set

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv)); // 2-bit RRPV, init to max
    memset(ship_signature, 0, sizeof(ship_signature));
    memset(ship_table, 1, sizeof(ship_table)); // optimistic: assume some reuse
    memset(last_addr, 0, sizeof(last_addr));
    memset(last_delta, 0, sizeof(last_delta));
    memset(stream_ctr, 0, sizeof(stream_ctr));

    // Leader set selection: evenly distribute sets
    leader_sets_sr.clear();
    leader_sets_br.clear();
    for (uint32_t i = 0; i < NUM_LEADER_SETS / 2; ++i) {
        leader_sets_sr.push_back(i * 2);      // Even sets for SRRIP leaders
        leader_sets_br.push_back(i * 2 + 1);  // Odd sets for BRRIP leaders
    }
}

// --- SHiP signature hash ---
inline uint8_t GetSignature(uint64_t PC) {
    return (PC ^ (PC >> 5) ^ (PC >> 13)) & (SHIP_TABLE_SIZE - 1);
}

// --- Streaming detector update ---
inline bool IsStreaming(uint32_t set, uint64_t paddr) {
    int64_t delta = paddr - last_addr[set];
    bool streaming = false;
    if (last_delta[set] != 0 && delta == last_delta[set]) {
        if (stream_ctr[set] < 3) ++stream_ctr[set];
    } else {
        if (stream_ctr[set] > 0) --stream_ctr[set];
    }
    streaming = (stream_ctr[set] >= 2);
    last_delta[set] = delta;
    last_addr[set] = paddr;
    return streaming;
}

// --- DRRIP insertion depth: 0 (SRRIP), 2 (BRRIP) ---
inline uint8_t DRRIP_InsertRRPV(uint32_t set) {
    // Leader sets always use fixed insertion
    for (auto s : leader_sets_sr)
        if (set == s) return 0; // SRRIP: insert at 0
    for (auto s : leader_sets_br)
        if (set == s) return 2; // BRRIP: insert at 2

    // Non-leader sets use PSEL
    return (PSEL >= (1 << (PSEL_BITS - 1))) ? 0 : 2;
}

// --- Victim selection (SRRIP) ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Standard SRRIP victim selection
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] < 3) ++rrpv[set][way];
    }
    return 0;
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
    // --- SHiP signature ---
    uint8_t sig = GetSignature(PC);

    // --- On hit ---
    if (hit) {
        rrpv[set][way] = 0; // MRU
        if (ship_table[sig] < 3) ++ship_table[sig];
        return;
    }

    // --- Streaming detection ---
    bool streaming = IsStreaming(set, paddr);

    // --- On fill (miss) ---
    ship_signature[set][way] = sig;

    // Streaming sets: bypass (do not insert) with 50% probability
    if (streaming) {
        // Bypass: insert at max RRPV, likely to be evicted soon
        rrpv[set][way] = 3;
        return;
    }

    // SHiP advice: dead signature, insert at distant RRPV
    if (ship_table[sig] == 0) {
        rrpv[set][way] = 3;
        return;
    }

    // DRRIP-controlled insertion depth
    rrpv[set][way] = DRRIP_InsertRRPV(set);
}

// --- On eviction: update SHiP and PSEL ---
void OnEviction(
    uint32_t set, uint32_t way
) {
    uint8_t sig = ship_signature[set][way];

    // If not reused (RRPV==3), mark as dead in SHiP
    if (rrpv[set][way] == 3) {
        if (ship_table[sig] > 0) --ship_table[sig];

        // Update PSEL for leader sets
        for (auto s : leader_sets_sr)
            if (set == s) {
                if (PSEL < ((1 << PSEL_BITS) - 1)) ++PSEL;
                break;
            }
        for (auto s : leader_sets_br)
            if (set == s) {
                if (PSEL > 0) --PSEL;
                break;
            }
    }
}

// --- Periodic decay of SHiP table ---
void DecayMetadata() {
    for (uint32_t i = 0; i < SHIP_TABLE_SIZE; ++i)
        if (ship_table[i] > 0) --ship_table[i];
}

// --- Print statistics ---
void PrintStats() {
    std::cout << "SDSB Policy: SHiP-lite + DRRIP + Streaming Bypass Hybrid\n";
    std::cout << "PSEL final value: " << PSEL << " (SRRIP > BRRIP if high)\n";
}
void PrintStats_Heartbeat() {}