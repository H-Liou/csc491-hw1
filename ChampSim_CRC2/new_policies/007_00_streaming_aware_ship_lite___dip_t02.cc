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
#define SHIP_SIG_ENTRIES (1 << SHIP_SIG_BITS) // 64 entries
uint8_t ship_outcome[SHIP_SIG_ENTRIES]; // 2-bit saturating counter per signature
uint8_t block_sig[LLC_SETS][LLC_WAYS];  // 6-bit signature per block

// --- Streaming detector: per-set last address, delta, and saturating counter ---
uint64_t last_addr[LLC_SETS];
int64_t last_delta[LLC_SETS];
uint8_t stream_ctr[LLC_SETS]; // 2-bit per set

#define STREAM_DETECT_THRESHOLD 3 // Counter saturates at 3
#define STREAM_DECAY_INTERVAL 4096 // Decay every 4096 fills
uint64_t fill_count = 0;

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv)); // all blocks start distant
    memset(ship_outcome, 0, sizeof(ship_outcome));
    memset(block_sig, 0, sizeof(block_sig));
    memset(last_addr, 0, sizeof(last_addr));
    memset(last_delta, 0, sizeof(last_delta));
    memset(stream_ctr, 0, sizeof(stream_ctr));
    for (uint32_t s = 0; s < LLC_SETS; ++s) {
        if (s < NUM_LEADER_SETS)
            is_leader_lip[s] = true, is_leader_bip[s] = false;
        else if (s >= LLC_SETS - NUM_LEADER_SETS)
            is_leader_lip[s] = false, is_leader_bip[s] = true;
        else
            is_leader_lip[s] = false, is_leader_bip[s] = false;
    }
    PSEL = 512;
    fill_count = 0;
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
    // RRIP victim selection: pick block with RRPV==3, else increment all and retry
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

    // --- Streaming detector: update per-set delta and counter ---
    int64_t delta = (int64_t)paddr - (int64_t)last_addr[set];
    if (last_addr[set] != 0 && delta == last_delta[set] && delta != 0) {
        // Monotonic stride detected
        if (stream_ctr[set] < 3) stream_ctr[set]++;
    } else {
        if (stream_ctr[set] > 0) stream_ctr[set]--;
    }
    last_delta[set] = delta;
    last_addr[set] = paddr;

    // --- On hit: set RRPV to 0, update SHiP outcome ---
    if (hit) {
        rrpv[set][way] = 0;
        block_sig[set][way] = sig;
        // Update SHiP outcome counter (max 3)
        if (ship_outcome[sig] < 3) ship_outcome[sig]++;
        // DIP set-dueling update
        if (is_leader_lip[set]) {
            if (PSEL < 1023) PSEL++;
        } else if (is_leader_bip[set]) {
            if (PSEL > 0) PSEL--;
        }
        return;
    }

    // --- Streaming-aware bypass/distant insertion ---
    bool streaming = (stream_ctr[set] >= STREAM_DETECT_THRESHOLD);

    // --- DIP: choose insertion policy ---
    bool use_lip = false;
    if (is_leader_lip[set])
        use_lip = true;
    else if (is_leader_bip[set])
        use_lip = false;
    else
        use_lip = (PSEL >= 512);

    uint8_t ins_rrpv = 2; // Default: BIP insert at 2, LIP at 3 except 1/32 fills at 2
    if (use_lip)
        ins_rrpv = 3;
    else
        ins_rrpv = ((rand() % 32) == 0) ? 2 : 3;

    // SHiP bias: if outcome counter for sig is high, insert at 0 (long reuse); if low, at 3 (dead)
    if (ship_outcome[sig] >= 2)
        ins_rrpv = 0;
    else if (ship_outcome[sig] == 0)
        ins_rrpv = 3;

    // Streaming detector: if streaming, force distant insertion or bypass
    if (streaming) {
        ins_rrpv = 3;
        // Optional: bypass fill (simulate by not updating block_sig, outcome, etc.)
        // For this implementation, we always fill but at distant RRPV.
    }

    rrpv[set][way] = ins_rrpv;
    block_sig[set][way] = sig;

    // --- On eviction: update SHiP outcome counter for victim block ---
    uint8_t victim_sig = block_sig[set][way];
    // If block was not reused (RRPV==3 at eviction), decrement outcome counter
    if (rrpv[set][way] == 3 && ship_outcome[victim_sig] > 0)
        ship_outcome[victim_sig]--;

    // --- Periodic decay of streaming counters ---
    fill_count++;
    if ((fill_count % STREAM_DECAY_INTERVAL) == 0) {
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            if (stream_ctr[s] > 0)
                stream_ctr[s]--;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "Streaming-Aware SHiP-Lite + DIP: Final statistics." << std::endl;
    std::cout << "PSEL: " << PSEL << std::endl;
    // Optionally print SHiP outcome histogram
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Optionally print SHiP outcome histogram, PSEL
}