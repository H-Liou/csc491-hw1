#include <vector>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- SHiP-lite metadata ---
#define SIG_BITS 6          // Per-block signature bits
#define SIG_TABLE_SIZE 64   // Global predictor table
uint8_t block_sig[LLC_SETS][LLC_WAYS];      // Per-block signature
uint8_t ship_ctr[SIG_TABLE_SIZE];           // 2-bit saturating outcome counter per signature

// --- Streaming detector metadata ---
uint64_t last_paddr[LLC_SETS];              // Last physical address in set
int64_t last_delta[LLC_SETS];               // Last delta
uint8_t stream_flag[LLC_SETS];              // 1 if streaming detected

// --- RRIP metadata ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// --- Set-dueling for SRRIP vs Streaming Bypass ---
#define DUEL_LEADER_SETS 32
#define PSEL_BITS 10
uint16_t psel = (1 << (PSEL_BITS-1));
uint8_t is_leader_srrip[LLC_SETS];      // 1 if SRRIP leader
uint8_t is_leader_stream[LLC_SETS];     // 1 if Streaming Bypass leader

void InitReplacementState() {
    // Initialize RRIP
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            rrpv[set][way] = 2;
            block_sig[set][way] = 0;
        }
    // Initialize SHiP-lite
    for (int i = 0; i < SIG_TABLE_SIZE; ++i)
        ship_ctr[i] = 1;
    // Streaming detection
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        last_paddr[set] = 0;
        last_delta[set] = 0;
        stream_flag[set] = 0;
    }
    // Set-dueling: assign leader sets
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        is_leader_srrip[set] = 0;
        is_leader_stream[set] = 0;
    }
    // First DUEL_LEADER_SETS sets are SRRIP-leader, next DUEL_LEADER_SETS are Stream-leader
    for (uint32_t i = 0; i < DUEL_LEADER_SETS; ++i)
        is_leader_srrip[i] = 1;
    for (uint32_t i = DUEL_LEADER_SETS; i < 2*DUEL_LEADER_SETS; ++i)
        is_leader_stream[i] = 1;
}

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
                ++rrpv[set][way];
    }
}

// Streaming detector update (simple monotonic delta check)
void UpdateStreamingDetector(uint32_t set, uint64_t paddr) {
    int64_t delta = (int64_t)paddr - (int64_t)last_paddr[set];
    if (last_delta[set] != 0 && delta == last_delta[set]) {
        // Streaming detected if same delta for 4 consecutive accesses
        if (stream_flag[set] < 4)
            stream_flag[set]++;
    } else {
        stream_flag[set] = 0;
    }
    last_delta[set] = delta;
    last_paddr[set] = paddr;
}

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
    // --- Signature extraction ---
    uint8_t sig = ((PC >> 2) ^ (set & 0x3F)) & ((1 << SIG_BITS)-1);

    // --- Streaming pattern update ---
    UpdateStreamingDetector(set, paddr);

    // --- SHiP-lite update ---
    uint8_t old_sig = block_sig[set][way];
    if (hit) {
        // On hit, reward signature
        if (ship_ctr[old_sig] < 3)
            ship_ctr[old_sig]++;
        rrpv[set][way] = 0; // MRU
    } else {
        // On eviction, penalize signature if not reused
        if (ship_ctr[old_sig] > 0)
            ship_ctr[old_sig]--;
        // New block: record signature
        block_sig[set][way] = sig;
        // --- Insertion policy selection ---
        // If leader set: use corresponding policy for PSEL update
        bool use_stream_bypass;
        if (is_leader_srrip[set])
            use_stream_bypass = false;
        else if (is_leader_stream[set])
            use_stream_bypass = true;
        else
            use_stream_bypass = (psel < (1 << (PSEL_BITS-1)));

        // Streaming + cold signature: bypass (set RRPV=3)
        if (stream_flag[set] >= 3 && ship_ctr[sig] <= 1) {
            rrpv[set][way] = 3; // Bypass
            // For leader sets, update PSEL
            if (is_leader_stream[set] && !hit && rrpv[set][way]==3 && ship_ctr[sig]<=1)
                if (psel < ((1<<PSEL_BITS)-1)) psel++;
        }
        // Streaming + hot signature: insert at distant RRPV to retain hot block
        else if (stream_flag[set] >= 3 && ship_ctr[sig] >= 2) {
            rrpv[set][way] = 2;
        }
        // Non-streaming: SHiP-guided insertion
        else {
            if (ship_ctr[sig] >= 2)
                rrpv[set][way] = 0;
            else
                rrpv[set][way] = 2;
            // For leader sets, update PSEL
            if (is_leader_srrip[set] && !hit && rrpv[set][way]<=2 && ship_ctr[sig]>=2)
                if (psel > 0) psel--;
        }
    }
}

void PrintStats() {
    int hot = 0, cold = 0;
    for (int i = 0; i < SIG_TABLE_SIZE; ++i) {
        if (ship_ctr[i] >= 2) hot++;
        else cold++;
    }
    std::cout << "SHiP-SDB: Hot PC signatures: " << hot << " / " << SIG_TABLE_SIZE << std::endl;
    std::cout << "SHiP-SDB: Cold PC signatures: " << cold << std::endl;
    int stream_sets = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        if (stream_flag[set] >= 3) stream_sets++;
    std::cout << "SHiP-SDB: Streaming sets detected: " << stream_sets << " / " << LLC_SETS << std::endl;
}

void PrintStats_Heartbeat() {
    int hot = 0;
    for (int i = 0; i < SIG_TABLE_SIZE; ++i)
        if (ship_ctr[i] >= 2) hot++;
    std::cout << "SHiP-SDB: Hot signature count: " << hot << std::endl;
    int stream_sets = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        if (stream_flag[set] >= 3) stream_sets++;
    std::cout << "SHiP-SDB: Streaming sets: " << stream_sets << std::endl;
}