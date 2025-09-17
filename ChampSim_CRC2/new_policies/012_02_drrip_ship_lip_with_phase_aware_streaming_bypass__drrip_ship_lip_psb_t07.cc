#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- DRRIP/DIP set-dueling ---
#define NUM_LEADER_SETS 64
#define PSEL_BITS 10
uint16_t psel;
uint8_t leader_set_type[LLC_SETS]; // 0: LIP, 1: BIP, 2: follower

// --- SHiP-lite Metadata ---
#define SIG_BITS 6
#define SHIP_CTR_BITS 2
uint8_t ship_signature[LLC_SETS][LLC_WAYS]; // 6-bit per block
uint8_t ship_ctr[LLC_SETS][LLC_WAYS];       // 2-bit per block

// --- RRIP Metadata (2 bits per block) ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// --- Phase Counter for Streaming/Temporal Locality (2 bits per set) ---
uint8_t phase_ctr[LLC_SETS]; // 0: normal, 1: streaming, 2: recent reuse, 3: phase-change

// --- Streaming Detector Metadata (per set) ---
#define STREAM_HIST_LEN 4
uint64_t stream_addr_hist[LLC_SETS][STREAM_HIST_LEN];
uint8_t stream_hist_ptr[LLC_SETS];

// --- Streaming Detector Threshold ---
#define STREAM_DETECT_COUNT 3 // at least 3 matching deltas

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv));
    memset(ship_signature, 0, sizeof(ship_signature));
    memset(ship_ctr, 1, sizeof(ship_ctr)); // Start at weak reuse
    memset(phase_ctr, 0, sizeof(phase_ctr));
    memset(stream_addr_hist, 0, sizeof(stream_addr_hist));
    memset(stream_hist_ptr, 0, sizeof(stream_hist_ptr));
    psel = (1 << (PSEL_BITS - 1));
    for (uint32_t s = 0; s < LLC_SETS; ++s) {
        if (s < NUM_LEADER_SETS / 2) leader_set_type[s] = 0; // LIP
        else if (s < NUM_LEADER_SETS) leader_set_type[s] = 1; // BIP
        else leader_set_type[s] = 2; // follower
    }
}

// --- PC Signature hashing ---
inline uint8_t get_signature(uint64_t PC) {
    return static_cast<uint8_t>((PC ^ (PC >> 7)) & ((1 << SIG_BITS) - 1));
}

// --- Streaming Detector: returns true if streaming detected ---
bool is_streaming(uint32_t set, uint64_t paddr) {
    uint8_t ptr = stream_hist_ptr[set];
    stream_addr_hist[set][ptr] = paddr;
    stream_hist_ptr[set] = (ptr + 1) % STREAM_HIST_LEN;
    if (ptr < STREAM_HIST_LEN - 1)
        return false; // not enough history yet
    int64_t ref_delta = (int64_t)stream_addr_hist[set][1] - (int64_t)stream_addr_hist[set][0];
    int match = 0;
    for (int i = 2; i < STREAM_HIST_LEN; ++i) {
        int64_t d = (int64_t)stream_addr_hist[set][i] - (int64_t)stream_addr_hist[set][i-1];
        if (d == ref_delta) match++;
    }
    return (match >= STREAM_DETECT_COUNT - 1);
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
    // Prefer invalid block
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (!current_set[way].valid)
            return way;

    // RRIP victim selection
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
    uint8_t sig = get_signature(PC);

    // Streaming detection and phase adaptation
    bool streaming = is_streaming(set, paddr);
    if (streaming) {
        // Enter streaming phase in this set
        phase_ctr[set] = 1;
    } else if (phase_ctr[set] == 1 && hit) {
        // Detected reuse after streaming, phase-change
        phase_ctr[set] = 3;
    } else if (hit) {
        phase_ctr[set] = 2; // recent reuse
    } else {
        // Decay phase counter (eventually returns to normal)
        if (phase_ctr[set] > 0) phase_ctr[set]--;
    }

    // On hit: promote block, increment reuse counter
    if (hit) {
        rrpv[set][way] = 0;
        if (ship_ctr[set][way] < 3) ship_ctr[set][way]++;
        ship_signature[set][way] = sig;
        return;
    }

    // DIP-style insertion depth: select between LIP/BIP
    uint8_t insertion_rrpv = 3; // LIP default (insert at distant RRPV)
    if (leader_set_type[set] == 0) { // LIP leader
        insertion_rrpv = 3;
    } else if (leader_set_type[set] == 1) { // BIP leader
        insertion_rrpv = (rand() % 32 == 0) ? 0 : 3;
    } else { // follower
        insertion_rrpv = (psel >= (1 << (PSEL_BITS - 1))) ? 3 : ((rand() % 32 == 0) ? 0 : 3);
    }

    // Phase-aware streaming bypass: during streaming phase, always insert at distant RRPV
    if (phase_ctr[set] == 1) {
        insertion_rrpv = 3;
    }

    // SHiP bias: strong reuse overrides insertion depth, insert at MRU
    if (ship_ctr[set][way] >= 2)
        insertion_rrpv = 0;

    rrpv[set][way] = insertion_rrpv;
    ship_signature[set][way] = sig;
    ship_ctr[set][way] = 1; // weak reuse on insertion

    // --- PSEL update ---
    if (leader_set_type[set] == 0) { // LIP leader
        if (hit) { if (psel < ((1 << PSEL_BITS) - 1)) psel++; }
        else { if (psel > 0) psel--; }
    } else if (leader_set_type[set] == 1) { // BIP leader
        if (hit) { if (psel > 0) psel--; }
        else { if (psel < ((1 << PSEL_BITS) - 1)) psel++; }
    }
}

// --- Print end-of-simulation statistics ---
void PrintStats() {
    int strong_reuse = 0, total_blocks = 0;
    int streaming_sets = 0, reuse_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s) {
        if (phase_ctr[s] == 1) streaming_sets++;
        if (phase_ctr[s] == 2) reuse_sets++;
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            if (ship_ctr[s][w] == 3) strong_reuse++;
            total_blocks++;
        }
    }
    std::cout << "DRRIP-SHiP-LIP-PSB Policy: DRRIP/DIP set-dueling + SHiP-lite + LIP + Phase-aware Streaming Bypass" << std::endl;
    std::cout << "Blocks with strong reuse (SHIP ctr==3): " << strong_reuse << "/" << total_blocks << std::endl;
    std::cout << "Streaming-phase sets: " << streaming_sets << "/" << LLC_SETS << std::endl;
    std::cout << "Reuse-phase sets: " << reuse_sets << "/" << LLC_SETS << std::endl;
    std::cout << "PSEL value: " << psel << std::endl;
}

// --- Print periodic (heartbeat) statistics ---
void PrintStats_Heartbeat() {
    int strong_reuse = 0, total_blocks = 0;
    int streaming_sets = 0, reuse_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s) {
        if (phase_ctr[s] == 1) streaming_sets++;
        if (phase_ctr[s] == 2) reuse_sets++;
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            if (ship_ctr[s][w] == 3) strong_reuse++;
            total_blocks++;
        }
    }
    std::cout << "Strong reuse blocks (heartbeat): " << strong_reuse << "/" << total_blocks
              << ", Streaming sets: " << streaming_sets << ", Reuse sets: " << reuse_sets << std::endl;
}