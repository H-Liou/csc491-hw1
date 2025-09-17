#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- DIP metadata ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];           // 2 bits per block
#define NUM_LEADER_SETS 64
#define PSEL_MAX 1023
uint16_t PSEL = PSEL_MAX / 2;
std::vector<uint32_t> lip_leader_sets, bip_leader_sets;

// --- SHiP-lite metadata ---
#define SHIP_SIG_BITS 6
#define SHIP_SIG_ENTRIES 1024
uint8_t ship_counter[SHIP_SIG_ENTRIES];     // 2 bits per entry

// --- Streaming detector metadata ---
uint64_t last_addr[LLC_SETS];               // 8 bytes per set
uint8_t stream_score[LLC_SETS];             // 2 bits per set

// --- Helper: get SHiP signature from PC ---
inline uint16_t get_signature(uint64_t PC) {
    return (PC ^ (PC >> 2)) & ((1 << SHIP_SIG_BITS) - 1);
}

// --- Helper: leader sets ---
inline bool is_lip_leader(uint32_t set) {
    for (auto s : lip_leader_sets) if (s == set) return true;
    return false;
}
inline bool is_bip_leader(uint32_t set) {
    for (auto s : bip_leader_sets) if (s == set) return true;
    return false;
}

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv));
    memset(ship_counter, 1, sizeof(ship_counter));
    memset(last_addr, 0, sizeof(last_addr));
    memset(stream_score, 0, sizeof(stream_score));
    lip_leader_sets.clear();
    bip_leader_sets.clear();
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i) {
        lip_leader_sets.push_back(i);
        bip_leader_sets.push_back(i + NUM_LEADER_SETS);
    }
    PSEL = PSEL_MAX / 2;
}

// --- Find victim ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Streaming bypass: if stream_score high, bypass (return invalid way, else victim)
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (!current_set[way].valid)
            return way;

    // Standard SRRIP victim selection
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            rrpv[set][way]++;
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
    uint16_t sig = get_signature(PC);

    // --- Streaming detector ---
    // If address delta is small and monotonic, increase stream_score; else decay
    uint64_t delta = (last_addr[set] == 0) ? 0 : std::abs((int64_t)paddr - (int64_t)last_addr[set]);
    if (delta > 0 && delta <= 128) { // 128-byte stride typical for streaming
        if (stream_score[set] < 3) stream_score[set]++;
    } else {
        if (stream_score[set] > 0) stream_score[set]--;
    }
    last_addr[set] = paddr;

    // --- SHiP update ---
    if (hit) {
        if (ship_counter[sig] < 3) ship_counter[sig]++;
        rrpv[set][way] = 0;
        return;
    }

    // --- Streaming bypass ---
    if (stream_score[set] >= 2) {
        // Bypass: do not insert into cache (simulate by setting rrpv to max so it will be evicted soon)
        rrpv[set][way] = 3;
        ship_counter[sig] = (ship_counter[sig] > 0) ? ship_counter[sig] - 1 : 0;
        return;
    }

    // --- Choose insertion depth ---
    uint8_t ins_rrpv = 3; // default distant

    // SHiP bias: if signature shows reuse, use near insert
    if (ship_counter[sig] >= 2)
        ins_rrpv = 1;
    else
        ins_rrpv = 3;

    // DIP set-dueling for insertion policy
    if (is_lip_leader(set)) {
        ins_rrpv = 3; // LIP: always distant
        if (hit && PSEL < PSEL_MAX) PSEL++;
    } else if (is_bip_leader(set)) {
        ins_rrpv = ((rand() % 32) == 0) ? 1 : 3; // BIP: rare near insert
        if (hit && ins_rrpv == 1 && PSEL > 0) PSEL--;
    } else {
        // Normal sets: choose by PSEL
        if (PSEL >= PSEL_MAX / 2) {
            ins_rrpv = 3; // LIP
        } else {
            ins_rrpv = ((rand() % 32) == 0) ? 1 : 3; // BIP
        }
    }

    // Insert block
    rrpv[set][way] = ins_rrpv;
    ship_counter[sig] = (ship_counter[sig] > 0) ? ship_counter[sig] - 1 : 0;
}

// --- Stats ---
void PrintStats() {
    std::cout << "DSSBH Policy: DIP (LIP/BIP set-dueling) + SHiP-lite + Streaming detector/bypass, PSEL=" << PSEL << std::endl;
}

void PrintStats_Heartbeat() {
    // Optionally print stream_score histogram
}