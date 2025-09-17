#include <vector>
#include <cstdint>
#include <cstring>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- Metadata Structures ---
struct LineMeta {
    uint8_t rrpv;         // 2 bits
    uint8_t ship_sig;     // 6 bits
};

std::vector<std::vector<LineMeta>> repl_meta;
std::vector<uint64_t> last_addr; // For streaming detection per set

// SHiP signature table: 4096 entries, 2 bits each
#define SHIP_SIG_BITS 6
#define SHIP_TABLE_SIZE (1 << SHIP_SIG_BITS)
uint8_t ship_outcome[SHIP_TABLE_SIZE];

// DRRIP set-dueling
#define PSEL_BITS 10
uint16_t psel = (1 << (PSEL_BITS - 1)); // 10 bits, init to mid
const int SRRIP_LEADER_SETS = 32;
const int BRRIP_LEADER_SETS = 32;
std::vector<uint8_t> set_type; // 0: follower, 1: SRRIP leader, 2: BRRIP leader

// Streaming detector: per-set, last address and stride
std::vector<uint64_t> stream_last_addr;
std::vector<int64_t> stream_last_delta;
std::vector<uint8_t> stream_confidence; // 2 bits per set

// --- Initialization ---
void InitReplacementState() {
    repl_meta.resize(LLC_SETS, std::vector<LineMeta>(LLC_WAYS));
    last_addr.resize(LLC_SETS, 0);
    set_type.resize(LLC_SETS, 0);

    // Assign leader sets for SRRIP and BRRIP
    for (uint32_t s = 0; s < LLC_SETS; ++s) {
        if (s < SRRIP_LEADER_SETS)
            set_type[s] = 1;
        else if (s < SRRIP_LEADER_SETS + BRRIP_LEADER_SETS)
            set_type[s] = 2;
        else
            set_type[s] = 0;
    }
    memset(ship_outcome, 1, sizeof(ship_outcome)); // Neutral initial outcome
    stream_last_addr.resize(LLC_SETS, 0);
    stream_last_delta.resize(LLC_SETS, 0);
    stream_confidence.resize(LLC_SETS, 0);
}

// --- Helper: SHiP signature ---
inline uint8_t GetSignature(uint64_t PC) {
    return (PC ^ (PC >> 2) ^ (PC >> 6)) & ((1 << SHIP_SIG_BITS) - 1);
}

// --- Streaming Detector ---
bool IsStreaming(uint32_t set, uint64_t paddr) {
    uint64_t last = stream_last_addr[set];
    int64_t delta = (last == 0) ? 0 : (int64_t)(paddr - last);
    bool stream = false;

    if (last != 0 && delta == stream_last_delta[set] && stream_confidence[set] >= 2) {
        stream = true;
    }

    // Update streaming detector
    if (last != 0 && delta == stream_last_delta[set]) {
        if (stream_confidence[set] < 3)
            stream_confidence[set]++;
    } else {
        stream_last_delta[set] = delta;
        stream_confidence[set] = 1;
    }
    stream_last_addr[set] = paddr;
    return stream;
}

// --- Find Victim ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Streaming: bypass or insert at distant RRPV
    bool streaming = IsStreaming(set, paddr);

    // Find victim with max RRPV
    for (int round = 0; round < 2; ++round) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (repl_meta[set][way].rrpv == 3)
                return way;
        }
        // If none found, increment all RRPVs
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (repl_meta[set][way].rrpv < 3)
                repl_meta[set][way].rrpv++;
    }
    // Should not reach here
    return 0;
}

// --- Update Replacement State ---
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
    LineMeta &meta = repl_meta[set][way];
    uint8_t sig = GetSignature(PC);

    // Streaming detector
    bool streaming = IsStreaming(set, paddr);

    // SHiP update: on hit, increment outcome; on miss, decrement
    if (hit)
        if (ship_outcome[sig] < 3) ship_outcome[sig]++;
    else
        if (ship_outcome[sig] > 0) ship_outcome[sig]--;

    // DRRIP set-dueling: update PSEL if in leader sets
    if (set_type[set] == 1) { // SRRIP leader
        if (hit && psel < ((1 << PSEL_BITS) - 1)) psel++;
    } else if (set_type[set] == 2) { // BRRIP leader
        if (hit && psel > 0) psel--;
    }

    // Insertion policy
    if (streaming) {
        // Streaming: insert at distant RRPV (3), or bypass (optional)
        meta.rrpv = 3;
        meta.ship_sig = sig;
        return;
    }

    // SHiP outcome controls insertion
    if (ship_outcome[sig] >= 2) {
        // High reuse: insert at RRPV=0 (long retention)
        meta.rrpv = 0;
    } else if (ship_outcome[sig] == 1) {
        // Neutral: DRRIP insertion
        bool use_brrip = (set_type[set] == 2) || ((set_type[set] == 0) && (psel < (1 << (PSEL_BITS - 1))));
        meta.rrpv = use_brrip ? ((rand() % 32 == 0) ? 2 : 3) : 2; // BRRIP: mostly distant, SRRIP: mid
    } else {
        // Low reuse: insert at RRPV=3 (short retention)
        meta.rrpv = 3;
    }
    meta.ship_sig = sig;
}

// --- Stats ---
void PrintStats() {
    std::cout << "SHiP-Lite+Streaming DRRIP Policy Stats" << std::endl;
}
void PrintStats_Heartbeat() {}