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

// DIP set-dueling: 64 leader sets per policy, 10-bit PSEL
#define NUM_LEADER_SETS 64
#define PSEL_MAX 1023
uint16_t PSEL = PSEL_MAX / 2;
std::vector<uint32_t> lip_leader_sets, bip_leader_sets;

// SHiP-lite: 6-bit PC signature per block, 2-bit outcome counter per signature
#define SHIP_SIG_BITS 6
#define SHIP_SIG_ENTRIES 1024
uint8_t ship_counter[SHIP_SIG_ENTRIES]; // 2 bits per entry

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
    memset(stream_conf, 0, sizeof(stream_conf));
    memset(last_addr, 0, sizeof(last_addr));
    // Randomly select leader sets
    lip_leader_sets.clear();
    bip_leader_sets.clear();
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i) {
        lip_leader_sets.push_back(i);
        bip_leader_sets.push_back(i + NUM_LEADER_SETS);
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
        // If none, increment all RRPV and evict
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            rrpv[set][way]++;
        return 0;
    }

    // Normal: SRRIP victim selection
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

    // On hit: update SHiP
    if (hit) {
        if (ship_counter[sig] < 3) ship_counter[sig]++;
        rrpv[set][way] = 0;
        return;
    }

    // On fill: decide insertion depth
    uint8_t ins_rrpv = 3; // default LIP: always distant insert

    // Streaming: bypass or distant insert
    if (stream_conf[set] >= 2) {
        ins_rrpv = 3;
    } else {
        // SHiP: if signature counter high, bias to near insert
        if (ship_counter[sig] >= 2)
            ins_rrpv = 0; // near insert
        else
            ins_rrpv = 3; // distant insert
    }

    // Set-dueling: leader sets update PSEL
    if (is_lip_leader(set)) {
        // LIP: always distant insert
        ins_rrpv = 3;
        if (hit && PSEL < PSEL_MAX) PSEL++;
    } else if (is_bip_leader(set)) {
        // BIP: near insert with low probability (1/32)
        if ((rand() % 32) == 0)
            ins_rrpv = 0;
        else
            ins_rrpv = 3;
        if (hit && ins_rrpv == 0 && PSEL > 0) PSEL--;
    } else {
        // Normal sets: choose insertion depth by PSEL
        if (PSEL >= PSEL_MAX / 2) {
            // LIP: always distant insert
            ins_rrpv = 3;
        } else {
            // BIP: near insert with low probability (1/32)
            if ((rand() % 32) == 0)
                ins_rrpv = 0;
            else
                ins_rrpv = 3;
        }
    }

    // Insert block
    rrpv[set][way] = ins_rrpv;
    ship_counter[sig] = (ship_counter[sig] > 0) ? ship_counter[sig] - 1 : 0;
}

// --- Stats ---
void PrintStats() {
    std::cout << "DSSA Policy: DIP (LIP/BIP) + SHiP-lite + Streaming Detector, PSEL=" << PSEL << std::endl;
}
void PrintStats_Heartbeat() {
    // Optionally print streaming confidence histogram
}