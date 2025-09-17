#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- DRRIP structures ---
static uint8_t rrpv[LLC_SETS][LLC_WAYS]; // 2 bits per line
static uint16_t psel = 512; // 10 bits for set-dueling
static const uint32_t NUM_LEADER_SETS = 64;
static std::vector<uint32_t> srrip_leader_sets;
static std::vector<uint32_t> brrip_leader_sets;

// --- SHiP-lite structures ---
static const uint32_t SHIP_SIG_BITS = 5;
static const uint32_t SHIP_SIG_ENTRIES = 1 << SHIP_SIG_BITS; // 32 entries
struct SHiPEntry {
    uint8_t counter; // 2 bits
};
static SHiPEntry ship_table[SHIP_SIG_ENTRIES];

// --- Streaming detector ---
static uint64_t last_addr[LLC_SETS]; // per-set last accessed address
static int64_t last_delta[LLC_SETS]; // per-set last delta
static uint8_t stream_score[LLC_SETS]; // per-set streaming confidence (0-3)

// Helper: get SHiP signature from PC
inline uint32_t get_signature(uint64_t PC) {
    return (PC ^ (PC >> 5)) & (SHIP_SIG_ENTRIES - 1);
}

// Helper: is leader set
inline bool is_srrip_leader(uint32_t set) {
    return std::find(srrip_leader_sets.begin(), srrip_leader_sets.end(), set) != srrip_leader_sets.end();
}
inline bool is_brrip_leader(uint32_t set) {
    return std::find(brrip_leader_sets.begin(), brrip_leader_sets.end(), set) != brrip_leader_sets.end();
}

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv)); // all lines distant
    memset(ship_table, 0, sizeof(ship_table));
    memset(last_addr, 0, sizeof(last_addr));
    memset(last_delta, 0, sizeof(last_delta));
    memset(stream_score, 0, sizeof(stream_score));

    // Select leader sets (round-robin)
    srrip_leader_sets.clear();
    brrip_leader_sets.clear();
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i) {
        srrip_leader_sets.push_back(i);
        brrip_leader_sets.push_back(i + NUM_LEADER_SETS);
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
    // Streaming detector: if streaming, prefer distant insertion/bypass
    bool streaming = (stream_score[set] >= 2);

    // Find victim with RRPV==3
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (rrpv[set][way] == 3) {
                return way;
            }
        }
        // Increment all RRPVs
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (rrpv[set][way] < 3)
                rrpv[set][way]++;
        }
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
    // --- Streaming detector update ---
    int64_t delta = int64_t(paddr) - int64_t(last_addr[set]);
    if (last_addr[set] != 0 && delta == last_delta[set] && abs(delta) > 64) {
        if (stream_score[set] < 3) stream_score[set]++;
    } else {
        if (stream_score[set] > 0) stream_score[set]--;
    }
    last_delta[set] = delta;
    last_addr[set] = paddr;

    // --- SHiP-lite update ---
    uint32_t sig = get_signature(PC);
    if (hit) {
        if (ship_table[sig].counter < 3) ship_table[sig].counter++;
    } else {
        if (ship_table[sig].counter > 0) ship_table[sig].counter--;
    }

    // --- DRRIP set-dueling update ---
    bool is_leader = false;
    if (is_srrip_leader(set)) {
        is_leader = true;
        if (hit) psel++;
        else psel--;
    } else if (is_brrip_leader(set)) {
        is_leader = true;
        if (hit) psel--;
        else psel++;
    }
    // Clamp psel
    if (psel > 1023) psel = 1023;
    if (psel < 0) psel = 0;

    // --- Insertion policy ---
    // Streaming: insert at distant RRPV (bypass if possible)
    if (stream_score[set] >= 2) {
        rrpv[set][way] = 3;
        return;
    }

    // SHiP-lite: insert at RRPV=0 if counter==3, else RRPV=2
    if (ship_table[sig].counter == 3) {
        rrpv[set][way] = 0;
        return;
    }

    // DRRIP: choose SRRIP or BRRIP
    bool use_brrip = false;
    if (is_srrip_leader(set)) use_brrip = false;
    else if (is_brrip_leader(set)) use_brrip = true;
    else use_brrip = (psel < 512); // 50/50 threshold

    if (use_brrip) {
        rrpv[set][way] = (rand() % 100 < 5) ? 0 : 2; // 5% at 0, else at 2
    } else {
        rrpv[set][way] = 2;
    }
}

// --- Statistics ---
void PrintStats() {
    std::cout << "SDSB (SHiP-Lite DRRIP + Streaming Bypass) replacement policy stats." << std::endl;
}
void PrintStats_Heartbeat() {}