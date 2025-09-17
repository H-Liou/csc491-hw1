#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- SHiP-Lite: 6-bit PC signatures, 2-bit outcome counters ---
#define SHIP_SIGNATURE_BITS 6
#define SHIP_SIGNATURE_MASK ((1 << SHIP_SIGNATURE_BITS) - 1)
#define SHIP_TABLE_SIZE 1024 // 1K entries, 2 bits each
uint8_t ship_table[SHIP_TABLE_SIZE]; // 2-bit saturating counters

uint8_t block_signature[LLC_SETS][LLC_WAYS]; // per-block signature

// --- DRRIP: 2-bit RRPV, 10-bit PSEL, 64 leader sets ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];
#define PSEL_BITS 10
uint16_t psel = 1 << (PSEL_BITS - 1); // Mid value
#define NUM_LEADER_SETS 64
bool is_srrip_leader[LLC_SETS];
bool is_brrip_leader[LLC_SETS];

// --- Streaming detector: per-set, last address and delta ---
uint64_t last_addr[LLC_SETS];
int64_t last_delta[LLC_SETS];
uint8_t stream_confidence[LLC_SETS]; // 2-bit confidence

// --- Parameters ---
#define SHIP_MAX 3
#define SHIP_MIN 0
#define STREAM_CONF_MAX 3
#define STREAM_CONF_MIN 0
#define STREAM_DETECT_THRESHOLD 3
#define BRRIP_INSERT_PROB 32 // 1/32 for BRRIP

// Helper: hash PC to signature
inline uint8_t GetSignature(uint64_t PC) {
    return (PC >> 2) & SHIP_SIGNATURE_MASK;
}

// Helper: hash address for streaming detection
inline int64_t AddrDelta(uint64_t a1, uint64_t a2) {
    return (int64_t)a1 - (int64_t)a2;
}

// Initialize replacement state
void InitReplacementState() {
    memset(ship_table, 0, sizeof(ship_table));
    memset(block_signature, 0, sizeof(block_signature));
    memset(rrpv, 2, sizeof(rrpv)); // SRRIP mid value
    psel = 1 << (PSEL_BITS - 1);
    memset(is_srrip_leader, 0, sizeof(is_srrip_leader));
    memset(is_brrip_leader, 0, sizeof(is_brrip_leader));
    memset(last_addr, 0, sizeof(last_addr));
    memset(last_delta, 0, sizeof(last_delta));
    memset(stream_confidence, 0, sizeof(stream_confidence));

    // Assign leader sets (first 32 for SRRIP, next 32 for BRRIP)
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i) {
        is_srrip_leader[i] = true;
        is_brrip_leader[NUM_LEADER_SETS + i] = true;
    }
}

// Find victim in the set
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Standard RRIP victim selection: evict block with RRPV==3
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (rrpv[set][way] == 3)
                return way;
        }
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] < 3)
                ++rrpv[set][way];
    }
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
    // --- Streaming detector update ---
    int64_t delta = AddrDelta(paddr, last_addr[set]);
    if (last_addr[set] != 0 && delta == last_delta[set]) {
        if (stream_confidence[set] < STREAM_CONF_MAX)
            stream_confidence[set]++;
    } else {
        if (stream_confidence[set] > STREAM_CONF_MIN)
            stream_confidence[set]--;
    }
    last_delta[set] = delta;
    last_addr[set] = paddr;

    // --- SHiP signature ---
    uint8_t sig = GetSignature(PC);

    // --- On hit ---
    if (hit) {
        rrpv[set][way] = 0; // Promote to MRU
        // Update SHiP outcome counter (increment, saturate)
        if (ship_table[block_signature[set][way]] < SHIP_MAX)
            ship_table[block_signature[set][way]]++;
    } else {
        // --- On miss/insert ---
        // Update SHiP outcome counter (decrement, saturate)
        if (ship_table[block_signature[set][way]] > SHIP_MIN)
            ship_table[block_signature[set][way]]--;

        // Streaming bypass logic: if high confidence, insert at distant RRPV
        bool streaming = (stream_confidence[set] >= STREAM_DETECT_THRESHOLD);

        // DRRIP insertion depth decision
        bool use_brrip = false;
        if (is_srrip_leader[set])
            use_brrip = false;
        else if (is_brrip_leader[set])
            use_brrip = true;
        else
            use_brrip = (psel < (1 << (PSEL_BITS - 1)));

        uint8_t insert_rrpv = 2; // Default: SRRIP mid
        if (streaming)
            insert_rrpv = 3; // Streaming: distant, minimize residency
        else if (ship_table[sig] == SHIP_MIN)
            insert_rrpv = 3; // Unfriendly PC: distant
        else if (ship_table[sig] == SHIP_MAX)
            insert_rrpv = 0; // Friendly PC: MRU
        else if (use_brrip)
            insert_rrpv = (rand() % BRRIP_INSERT_PROB == 0) ? 2 : 3; // BRRIP: mostly distant

        rrpv[set][way] = insert_rrpv;
        block_signature[set][way] = sig;

        // DRRIP PSEL update (leader sets only)
        if (is_srrip_leader[set]) {
            if (!hit && insert_rrpv == 2) { // SRRIP leader miss
                if (psel < ((1 << PSEL_BITS) - 1)) psel++;
            }
        } else if (is_brrip_leader[set]) {
            if (!hit && insert_rrpv >= 3) { // BRRIP leader miss
                if (psel > 0) psel--;
            }
        }
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    int ship_friendly = 0, ship_unfriendly = 0;
    for (int i = 0; i < SHIP_TABLE_SIZE; ++i) {
        if (ship_table[i] == SHIP_MAX) ship_friendly++;
        if (ship_table[i] == SHIP_MIN) ship_unfriendly++;
    }
    std::cout << "SHiP-Lite-DRRIP: Friendly PCs: " << ship_friendly << " / " << SHIP_TABLE_SIZE << std::endl;
    std::cout << "SHiP-Lite-DRRIP: Unfriendly PCs: " << ship_unfriendly << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    int streaming_sets = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        if (stream_confidence[set] >= STREAM_DETECT_THRESHOLD)
            streaming_sets++;
    std::cout << "SHiP-Lite-DRRIP: Streaming sets: " << streaming_sets << std::endl;
}