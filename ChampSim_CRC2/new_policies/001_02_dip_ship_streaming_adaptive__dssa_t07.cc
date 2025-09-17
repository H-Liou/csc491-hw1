#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- Metadata structures ---
// 2 bits RRPV per block
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// DIP: 32 LIP leader sets, 32 BIP leader sets, 10-bit PSEL
#define NUM_LEADER_SETS 64
#define PSEL_MAX 1023
uint16_t PSEL = PSEL_MAX / 2;
std::vector<uint32_t> lip_leader_sets, bip_leader_sets;

// SHiP-lite: 6-bit PC signature per block, 2-bit outcome counter per signature
#define SHIP_SIG_BITS 6
#define SHIP_SIG_ENTRIES 1024
uint8_t ship_counter[SHIP_SIG_ENTRIES]; // 2 bits per entry

// Per-block: 2-bit dead-block counter
uint8_t dead_counter[LLC_SETS][LLC_WAYS];

// Streaming detector: 2 bits per set (confidence), last address per set
uint8_t stream_conf[LLC_SETS];
uint64_t last_addr[LLC_SETS];

// Helper: get SHiP signature from PC
inline uint16_t get_signature(uint64_t PC) {
    return (PC ^ (PC >> 2)) & ((1 << SHIP_SIG_BITS) - 1);
}

// Helper: is set a leader set?
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
    memset(dead_counter, 0, sizeof(dead_counter));
    memset(stream_conf, 0, sizeof(stream_conf));
    memset(last_addr, 0, sizeof(last_addr));
    lip_leader_sets.clear();
    bip_leader_sets.clear();
    // Assign leader sets: first 32 LIP, next 32 BIP
    for (uint32_t i = 0; i < NUM_LEADER_SETS / 2; ++i) {
        lip_leader_sets.push_back(i);
        bip_leader_sets.push_back(i + NUM_LEADER_SETS / 2);
    }
}

// --- Streaming detector: update confidence ---
void update_streaming(uint32_t set, uint64_t addr) {
    uint64_t delta = addr - last_addr[set];
    if (last_addr[set] != 0) {
        if (delta == 64 || delta == -64) { // 64B stride
            if (stream_conf[set] < 3) stream_conf[set]++;
        } else {
            if (stream_conf[set] > 0) stream_conf[set]--;
        }
    }
    last_addr[set] = addr;
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
    // Streaming: bypass if confidence high
    if (stream_conf[set] >= 2) {
        // Find invalid block
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (!current_set[way].valid)
                return way;
        // Otherwise, evict block with max RRPV
        uint32_t victim = 0;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        // If none, increment all RRPV and evict first
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            rrpv[set][way]++;
        return 0;
    }
    // Normal: SRRIP victim selection (LIP/BIP insertion handled in Update)
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
    // Update streaming detector
    update_streaming(set, paddr);

    // Get SHiP signature
    uint16_t sig = get_signature(PC);

    // On hit: update SHiP and dead-block counter
    if (hit) {
        if (ship_counter[sig] < 3) ship_counter[sig]++;
        if (dead_counter[set][way] < 3) dead_counter[set][way]++;
        rrpv[set][way] = 0;
        return;
    }

    // On fill: decide insertion depth
    uint8_t ins_rrpv = 2; // default SRRIP insertion

    // Streaming: bypass or distant insert
    if (stream_conf[set] >= 2) {
        ins_rrpv = 3;
    } else {
        // Dead-block predictor: if dead_counter==0, distant insert
        if (dead_counter[set][way] == 0)
            ins_rrpv = 3;
        // SHiP: if signature counter low, distant insert
        else if (ship_counter[sig] <= 1)
            ins_rrpv = 3;
        else {
            // DIP logic: leader sets update PSEL, normal sets follow PSEL
            if (is_lip_leader(set)) {
                ins_rrpv = 3; // LIP: insert at distant RRPV
                if (hit && PSEL < PSEL_MAX) PSEL++;
            } else if (is_bip_leader(set)) {
                ins_rrpv = (rand() % 32 == 0) ? 2 : 3; // BIP: insert at near RRPV 1/32, else distant
                if (hit && ins_rrpv == 2 && PSEL > 0) PSEL--;
            } else {
                // Normal sets: follow DIP selector
                if (PSEL >= PSEL_MAX / 2) // favor LIP
                    ins_rrpv = 3;
                else // favor BIP
                    ins_rrpv = (rand() % 32 == 0) ? 2 : 3;
            }
        }
    }

    // Insert block
    rrpv[set][way] = ins_rrpv;
    dead_counter[set][way] = 0;
    ship_counter[sig] = (ship_counter[sig] > 0) ? ship_counter[sig] - 1 : 0;
}

// --- Stats ---
void PrintStats() {
    std::cout << "DSSA Policy: DIP(LIP/BIP)+SHiP-lite+Streaming+Dead-block, PSEL=" << PSEL << std::endl;
}
void PrintStats_Heartbeat() {
    // Optionally print streaming confidence histogram
}