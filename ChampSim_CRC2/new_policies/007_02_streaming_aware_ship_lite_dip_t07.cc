#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- DIP: 2-bit RRPV per block ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// --- DIP set-dueling: 32 leader sets for LIP, 32 for BIP ---
#define NUM_LEADER_SETS 32
uint16_t PSEL = 512; // 10-bit counter
bool is_leader_lip[LLC_SETS];
bool is_leader_bip[LLC_SETS];

// --- SHiP-lite: 6-bit PC signature per block, 2-bit outcome counter per signature ---
#define SHIP_SIG_BITS 6
#define SHIP_SIG_ENTRIES (1 << SHIP_SIG_BITS) // 64 entries, 2 bits each
uint8_t ship_outcome[SHIP_SIG_ENTRIES];
uint8_t block_sig[LLC_SETS][LLC_WAYS];

// --- Streaming Detector: 2-bit recent delta history per set ---
uint8_t stream_hist[LLC_SETS];
uint64_t last_addr[LLC_SETS];

// --- Streaming threshold ---
#define STREAM_DETECT_THRESH 2

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv));
    memset(ship_outcome, 0, sizeof(ship_outcome));
    memset(block_sig, 0, sizeof(block_sig));
    memset(stream_hist, 0, sizeof(stream_hist));
    memset(last_addr, 0, sizeof(last_addr));
    for (uint32_t s = 0; s < LLC_SETS; ++s) {
        is_leader_lip[s] = (s < NUM_LEADER_SETS);
        is_leader_bip[s] = (s >= LLC_SETS - NUM_LEADER_SETS);
    }
    PSEL = 512;
}

// --- Find victim: RRIP victim selection ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] < 3)
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
    // --- SHiP signature extraction ---
    uint8_t sig = (PC ^ (paddr >> 6)) & (SHIP_SIG_ENTRIES - 1);

    // --- Streaming detector: update delta history ---
    uint64_t addr_blk = paddr >> 6;
    uint8_t delta = (last_addr[set] > 0) ? (uint8_t)(addr_blk - (last_addr[set] >> 6)) : 0;
    if (delta == 1 || delta == (uint8_t)-1) {
        if (stream_hist[set] < 3) stream_hist[set]++;
    } else if (stream_hist[set] > 0) {
        stream_hist[set]--;
    }
    last_addr[set] = paddr;

    // --- On hit: set RRPV to 0, update SHiP outcome ---
    if (hit) {
        rrpv[set][way] = 0;
        block_sig[set][way] = sig;
        if (ship_outcome[sig] < 3) ship_outcome[sig]++;
        // DIP set-dueling update
        if (is_leader_lip[set])
            if (PSEL < 1023) PSEL++;
        else if (is_leader_bip[set])
            if (PSEL > 0) PSEL--;
        return;
    }

    // --- Streaming detection: bypass/distant insertion if streaming detected ---
    bool is_streaming = (stream_hist[set] >= STREAM_DETECT_THRESH);

    // --- DIP insertion depth selection ---
    bool use_lip = false;
    if (is_leader_lip[set])
        use_lip = true;
    else if (is_leader_bip[set])
        use_lip = false;
    else
        use_lip = (PSEL >= 512);

    uint8_t ins_rrpv = 3; // LIP: insert at distant
    if (!use_lip) {
        // BIP: insert at distant except 1/32 fills at 0
        ins_rrpv = ((rand() % 32) == 0) ? 0 : 3;
    }

    // --- SHiP-lite bias: if high outcome, insert at 0; if low, at distant
    if (ship_outcome[sig] >= 2)
        ins_rrpv = 0;
    else if (ship_outcome[sig] == 0)
        ins_rrpv = 3;

    // --- Streaming override: if streaming detected, force distant or bypass ---
    if (is_streaming)
        ins_rrpv = 3; // could bypass, but for safety: insert at distant

    rrpv[set][way] = ins_rrpv;
    block_sig[set][way] = sig;

    // --- On eviction: update SHiP outcome counter for victim block ---
    uint8_t victim_sig = block_sig[set][way];
    if (rrpv[set][way] == 3 && ship_outcome[victim_sig] > 0)
        ship_outcome[victim_sig]--;

    // No periodic decay needed for streaming logic (fast phase change)
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "Streaming-Aware SHiP-Lite DIP: Final statistics." << std::endl;
    std::cout << "PSEL: " << PSEL << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Optionally print PSEL, streaming histograms
}