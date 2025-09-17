#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- SHiP-lite Structures ---
// 5-bit PC signature (per block)
uint8_t pc_signature[LLC_SETS][LLC_WAYS];
// 2-bit reuse counter for each signature (per block)
uint8_t reuse_counter[LLC_SETS][LLC_WAYS];

// --- Signature outcome table (per set, 32 entries) ---
#define SHIP_SIG_ENTRIES 32
struct ShipSigEntry {
    uint8_t counter; // 2 bits
    uint8_t valid;
    uint8_t tag; // 5 bits
};
ShipSigEntry ship_sig_table[LLC_SETS][SHIP_SIG_ENTRIES];

// --- Streaming Detector (per set) ---
struct StreamDetect {
    uint64_t last_addr;
    int64_t last_delta;
    uint8_t stream_count; // 2 bits
    bool is_streaming;
};
StreamDetect stream_detect[LLC_SETS];

// --- DRRIP Structures ---
uint8_t rrpv[LLC_SETS][LLC_WAYS]; // 2-bit RRPV
#define NUM_LEADER_SETS 64
uint32_t leader_sets[NUM_LEADER_SETS];
uint16_t PSEL = 512; // 10 bits, midpoint

inline bool IsSRRIPLeader(uint32_t set) {
    for (int i = 0; i < NUM_LEADER_SETS/2; ++i)
        if (leader_sets[i] == set) return true;
    return false;
}
inline bool IsBRRIPLeader(uint32_t set) {
    for (int i = NUM_LEADER_SETS/2; i < NUM_LEADER_SETS; ++i)
        if (leader_sets[i] == set) return true;
    return false;
}

// --- Helper: Signature hash ---
inline uint8_t GetSignature(uint64_t PC) {
    // Use lower 5 bits of CRC32 of PC for compact signature
    return champsim_crc32(PC) & 0x1F;
}

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv)); // RRPV to max
    memset(pc_signature, 0, sizeof(pc_signature));
    memset(reuse_counter, 0, sizeof(reuse_counter));
    memset(stream_detect, 0, sizeof(stream_detect));
    memset(ship_sig_table, 0, sizeof(ship_sig_table));
    for (int i = 0; i < NUM_LEADER_SETS; ++i)
        leader_sets[i] = (LLC_SETS / NUM_LEADER_SETS) * i;
    PSEL = 512;
}

// --- Streaming detector ---
bool DetectStreaming(uint32_t set, uint64_t paddr) {
    StreamDetect &sd = stream_detect[set];
    int64_t delta = paddr - sd.last_addr;
    if (sd.last_addr != 0) {
        if (delta == sd.last_delta && delta != 0) {
            if (sd.stream_count < 3) ++sd.stream_count;
        } else {
            if (sd.stream_count > 0) --sd.stream_count;
        }
        sd.is_streaming = (sd.stream_count >= 2);
    }
    sd.last_delta = delta;
    sd.last_addr = paddr;
    return sd.is_streaming;
}

// --- SHiP-lite: find/allocate signature entry in table ---
ShipSigEntry* FindSigEntry(uint32_t set, uint8_t sig) {
    // Simple direct-mapped 32-entry per set
    ShipSigEntry &entry = ship_sig_table[set][sig];
    if (!entry.valid || entry.tag != sig) {
        entry.counter = 1; // default initial value
        entry.valid = 1;
        entry.tag = sig;
    }
    return &entry;
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
    // Standard SRRIP victim selection
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] < 3)
                ++rrpv[set][way];
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
    // --- Streaming detection ---
    bool streaming = DetectStreaming(set, paddr);

    uint8_t sig = GetSignature(PC);
    ShipSigEntry* sig_entry = FindSigEntry(set, sig);

    // --- On hit ---
    if (hit) {
        rrpv[set][way] = 0; // Promote to MRU
        // Update reuse counter and signature outcome
        if (reuse_counter[set][way] < 3) ++reuse_counter[set][way];
        if (sig_entry->counter < 3) ++sig_entry->counter;
        // DRRIP: update PSEL for leader sets
        if (IsSRRIPLeader(set)) {
            if (PSEL < 1023) ++PSEL;
        } else if (IsBRRIPLeader(set)) {
            if (PSEL > 0) --PSEL;
        }
        return;
    }

    // --- On fill ---
    // Streaming phase: bypass fill (do not insert into cache)
    if (streaming) {
        rrpv[set][way] = 3; // Insert at distant RRPV ("bypass")
        pc_signature[set][way] = sig;
        reuse_counter[set][way] = 0;
        return;
    }

    // SHiP-lite: Use signature outcome to choose insertion depth
    bool reuse_bias = (sig_entry->counter >= 2);

    // DRRIP: Set-dueling insertion depth selection
    bool use_srrip = false;
    if (IsSRRIPLeader(set)) use_srrip = true;
    else if (IsBRRIPLeader(set)) use_srrip = false;
    else use_srrip = (PSEL >= 512);

    // If signature shows frequent reuse, insert at MRU (rrpv=0)
    if (reuse_bias) {
        rrpv[set][way] = 0;
    } else {
        // Else, use DRRIP insertion depth control
        if (use_srrip) {
            rrpv[set][way] = 2; // SRRIP: insert at RRPV=2
        } else {
            rrpv[set][way] = (rand() % 32 == 0) ? 2 : 3; // BRRIP: mostly distant
        }
    }
    pc_signature[set][way] = sig;
    reuse_counter[set][way] = 0;
}

// --- Print statistics ---
void PrintStats() {
    std::cout << "SSDH Policy: SHiP-lite + Streaming Bypass + DRRIP Set-Dueling\n";
}
void PrintStats_Heartbeat() {}