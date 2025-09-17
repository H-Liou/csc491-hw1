#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- DRRIP Set-Dueling ---
#define NUM_LEADER_SETS 64
#define PSEL_MAX 1023

// --- SHiP-lite ---
#define SHIP_SIG_BITS 6
#define SHIP_SIG_ENTRIES (1 << SHIP_SIG_BITS)
#define SHIP_COUNTER_BITS 2

// --- Streaming Detector ---
#define STREAM_WIN_SIZE 4
#define STREAM_DELTA_THRESHOLD 4

// Replacement state structures
struct RRIPEntry {
    uint8_t rrpv; // 2 bits
    uint8_t ship_sig; // 6 bits
};

struct SHIPEntry {
    uint8_t counter; // 2 bits
};

std::vector<RRIPEntry> rrip_state(LLC_SETS * LLC_WAYS);
std::vector<SHIPEntry> ship_table(SHIP_SIG_ENTRIES);

// DRRIP set-dueling
std::vector<uint8_t> is_leader_srrip(LLC_SETS, 0);
std::vector<uint8_t> is_leader_brrip(LLC_SETS, 0);
uint16_t psel = PSEL_MAX / 2;

// Streaming detector per set
struct StreamDetect {
    uint64_t last_addr[STREAM_WIN_SIZE];
    int idx;
    bool streaming;
};
std::vector<StreamDetect> stream_state(LLC_SETS);

// Helper: Get SHiP signature
inline uint8_t get_ship_sig(uint64_t PC) {
    return (PC ^ (PC >> 6)) & (SHIP_SIG_ENTRIES - 1);
}

// Helper: DRRIP insertion policy
inline uint8_t get_drrip_insert_rrpv(uint32_t set) {
    // Leader sets: force SRRIP or BRRIP
    if (is_leader_srrip[set]) return 2; // SRRIP: insert at RRPV=2
    if (is_leader_brrip[set]) return (rand() % 32 == 0) ? 2 : 3; // BRRIP: insert at RRPV=3 (rarely at 2)
    // Follower sets: use PSEL
    return (psel >= PSEL_MAX / 2) ? 2 : ((rand() % 32 == 0) ? 2 : 3);
}

// Helper: SHiP insertion policy
inline uint8_t get_ship_insert_rrpv(uint8_t sig) {
    return (ship_table[sig].counter > 0) ? 2 : 3;
}

// Helper: Streaming detector
bool is_streaming(uint32_t set, uint64_t addr) {
    StreamDetect &sd = stream_state[set];
    sd.last_addr[sd.idx] = addr;
    sd.idx = (sd.idx + 1) % STREAM_WIN_SIZE;
    // Check monotonic deltas
    int deltas = 0;
    for (int i = 1; i < STREAM_WIN_SIZE; ++i) {
        uint64_t prev = sd.last_addr[(sd.idx + STREAM_WIN_SIZE - i) % STREAM_WIN_SIZE];
        uint64_t curr = sd.last_addr[(sd.idx + STREAM_WIN_SIZE - i + 1) % STREAM_WIN_SIZE];
        if (curr > prev && (curr - prev) < (64 * LLC_WAYS)) deltas++;
    }
    sd.streaming = (deltas >= STREAM_DELTA_THRESHOLD);
    return sd.streaming;
}

// Initialize replacement state
void InitReplacementState() {
    // DRRIP leader sets
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i) {
        is_leader_srrip[i] = 1;
        is_leader_brrip[LLC_SETS - 1 - i] = 1;
    }
    // RRIP and SHiP state
    for (size_t i = 0; i < rrip_state.size(); ++i) {
        rrip_state[i].rrpv = 3;
        rrip_state[i].ship_sig = 0;
    }
    for (size_t i = 0; i < ship_table.size(); ++i) {
        ship_table[i].counter = 1;
    }
    // Streaming detector
    for (size_t i = 0; i < stream_state.size(); ++i) {
        memset(stream_state[i].last_addr, 0, sizeof(stream_state[i].last_addr));
        stream_state[i].idx = 0;
        stream_state[i].streaming = false;
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
    // Streaming bypass: if streaming, prefer to evict oldest (highest RRPV)
    bool streaming = is_streaming(set, paddr);
    uint32_t victim = LLC_WAYS;
    while (victim == LLC_WAYS) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            uint32_t idx = set * LLC_WAYS + way;
            if (rrip_state[idx].rrpv == 3) {
                victim = way;
                break;
            }
        }
        if (victim == LLC_WAYS) {
            // Increment all RRPVs
            for (uint32_t way = 0; way < LLC_WAYS; ++way) {
                uint32_t idx = set * LLC_WAYS + way;
                rrip_state[idx].rrpv = std::min<uint8_t>(3, rrip_state[idx].rrpv + 1);
            }
        }
    }
    return victim;
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
    uint32_t idx = set * LLC_WAYS + way;
    uint8_t sig = get_ship_sig(PC);

    // Streaming detection
    bool streaming = is_streaming(set, paddr);

    // DRRIP set-dueling update
    if (is_leader_srrip[set]) {
        if (hit) psel = std::min<uint16_t>(PSEL_MAX, psel + 1);
        else     psel = (psel > 0) ? psel - 1 : 0;
    } else if (is_leader_brrip[set]) {
        if (hit) psel = (psel > 0) ? psel - 1 : 0;
        else     psel = std::min<uint16_t>(PSEL_MAX, psel + 1);
    }

    // SHiP update
    if (hit) {
        ship_table[sig].counter = std::min<uint8_t>((1 << SHIP_COUNTER_BITS) - 1, ship_table[sig].counter + 1);
        rrip_state[idx].rrpv = 0;
    } else {
        ship_table[sig].counter = (ship_table[sig].counter > 0) ? ship_table[sig].counter - 1 : 0;
    }

    // On fill (miss), set RRPV and signature
    if (!hit) {
        rrip_state[idx].ship_sig = sig;
        if (streaming) {
            rrip_state[idx].rrpv = 3; // streaming: insert at distant RRPV
        } else {
            // Hybrid: use SHiP prediction, fallback to DRRIP
            uint8_t ship_rrpv = get_ship_insert_rrpv(sig);
            uint8_t drrip_rrpv = get_drrip_insert_rrpv(set);
            rrip_state[idx].rrpv = std::min(ship_rrpv, drrip_rrpv);
        }
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "SHiP-Lite+DRRIP+Streaming Policy Stats" << std::endl;
    // Optionally print PSEL, SHiP table summary
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Optionally print streaming detection rate, etc.
}