#include <vector>
#include <cstdint>
#include <cstring>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- Metadata Structures ---

// 2 bits/line RRPV
uint8_t RRPV[LLC_SETS][LLC_WAYS];

// 5 bits/line SHiP signature (from PC)
uint8_t SHIP_SIG[LLC_SETS][LLC_WAYS];

// SHiP table: 2K entries, 2 bits each
#define SHIP_TABLE_SIZE 2048
uint8_t SHIP_TABLE[SHIP_TABLE_SIZE];

// Streaming detector: 2 bytes/set (prev_addr, stride counter)
struct StreamingSetInfo {
    uint64_t last_addr;
    int8_t stride_count; // signed: negative for down, positive for up
    uint8_t streaming;   // 1 = streaming detected
};
StreamingSetInfo STREAM_DETECT[LLC_SETS];

// Set-dueling: 32 leader sets for SRRIP, 32 for BRRIP, 10-bit PSEL
#define LEADER_SETS 32
uint32_t SRRIP_LEADER_SETS[LEADER_SETS];
uint32_t BRRIP_LEADER_SETS[LEADER_SETS];
uint16_t PSEL = 512; // [0,1023], >512: prefer SRRIP

// Address hash (6 bits) for last filled lines in set (used for address-based reuse hint)
uint8_t ADDR_HASH[LLC_SETS][LLC_WAYS];

// Helper: Hash PC to SHiP signature
inline uint16_t ship_hash(uint64_t pc) {
    return ((pc >> 2) ^ (pc >> 5) ^ (pc >> 12)) & (SHIP_TABLE_SIZE - 1);
}

// Helper: Hash address for address-based reuse (6 bits)
inline uint8_t addr_hash(uint64_t addr) {
    return ((addr >> 6) ^ (addr >> 13) ^ (addr >> 21)) & 0x3F;
}

// Identify if set is leader for SRRIP/BRRIP
inline bool is_srrip_leader(uint32_t set) {
    for (int i = 0; i < LEADER_SETS; i++)
        if (SRRIP_LEADER_SETS[i] == set) return true;
    return false;
}
inline bool is_brrip_leader(uint32_t set) {
    for (int i = 0; i < LEADER_SETS; i++)
        if (BRRIP_LEADER_SETS[i] == set) return true;
    return false;
}

// --- Initialization ---
void InitReplacementState() {
    memset(RRPV, 3, sizeof(RRPV));
    memset(SHIP_SIG, 0, sizeof(SHIP_SIG));
    memset(SHIP_TABLE, 0, sizeof(SHIP_TABLE));
    memset(STREAM_DETECT, 0, sizeof(STREAM_DETECT));
    memset(ADDR_HASH, 0, sizeof(ADDR_HASH));
    // Randomly choose leader sets for SRRIP and BRRIP
    for (int i = 0; i < LEADER_SETS; i++) {
        SRRIP_LEADER_SETS[i] = (i * 13) % LLC_SETS;
        BRRIP_LEADER_SETS[i] = ((i * 31) + 37) % LLC_SETS;
    }
    PSEL = 512;
}

// --- Streaming Detector ---
void update_streaming_detector(uint32_t set, uint64_t addr) {
    StreamingSetInfo &si = STREAM_DETECT[set];
    int64_t delta = (int64_t)addr - (int64_t)si.last_addr;
    if (si.last_addr != 0) {
        // Check stride direction
        if (delta == 64) si.stride_count++;  // Up scan (cache line size)
        else if (delta == -64) si.stride_count--; // Down scan
        else if (delta != 0) si.stride_count = 0;
        // Streaming detected if stride count exceeds threshold
        if (si.stride_count >= 8 || si.stride_count <= -8)
            si.streaming = 1;
        else if (si.stride_count == 0)
            si.streaming = 0;
    }
    si.last_addr = addr;
}

// --- Victim Selection ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Streaming set: bypass if detected and SHiP reuse low
    StreamingSetInfo &si = STREAM_DETECT[set];
    uint16_t sig = ship_hash(PC);
    bool streaming = (si.streaming == 1);
    bool low_ship = (SHIP_TABLE[sig] < 2);

    if (streaming && low_ship) {
        // Find an invalid block (if any), else evict oldest (highest RRPV)
        for (uint32_t way = 0; way < LLC_WAYS; way++)
            if (current_set[way].valid == 0)
                return way;
        // All valid: pick a block to evict (bypass fill later)
        uint32_t victim = 0;
        uint8_t max_rrpv = RRPV[set][0];
        for (uint32_t way = 1; way < LLC_WAYS; way++) {
            if (RRPV[set][way] > max_rrpv) {
                max_rrpv = RRPV[set][way];
                victim = way;
            }
        }
        return victim;
    }

    // Normal: SRRIP victim selection
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; way++) {
            if (RRPV[set][way] == 3)
                return way;
        }
        // Increment RRPV for all
        for (uint32_t way = 0; way < LLC_WAYS; way++)
            if (RRPV[set][way] < 3) RRPV[set][way]++;
    }
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
    // Update streaming detector
    update_streaming_detector(set, paddr);

    // SHiP signature
    uint16_t sig = ship_hash(PC);

    // Address hash
    uint8_t ahash = addr_hash(paddr);

    // Update SHiP table (2 bits/counter)
    if (hit) {
        if (SHIP_TABLE[sig] < 3) SHIP_TABLE[sig]++;
    } else {
        if (SHIP_TABLE[sig] > 0) SHIP_TABLE[sig]--;
    }

    // Update address hash per line (for future fills)
    ADDR_HASH[set][way] = ahash;

    // Streaming info
    StreamingSetInfo &si = STREAM_DETECT[set];
    bool streaming = (si.streaming == 1);

    // Choose insertion depth
    uint8_t ins_rrpv = 2; // Default: SRRIP

    // Set-dueling leader sets
    bool srrip_leader = is_srrip_leader(set);
    bool brrip_leader = is_brrip_leader(set);

    // Baseline insertion
    if (srrip_leader) ins_rrpv = 2; // SRRIP: insert at RRPV=2
    else if (brrip_leader) ins_rrpv = ((rand() & 0x1F) == 0) ? 2 : 3; // BRRIP: insert at RRPV=2 (rare), else 3
    else ins_rrpv = (PSEL > 512) ? 2 : (((rand() & 0x1F) == 0) ? 2 : 3);

    // Override for SHiP
    if (SHIP_TABLE[sig] >= 2) ins_rrpv = 0; // High predicted reuse (MRU)

    // Override for address hash (if matching with other lines in set)
    int addr_match = 0;
    for (uint32_t w = 0; w < LLC_WAYS; w++)
        if (w != way && ADDR_HASH[set][w] == ahash)
            addr_match++;
    if (addr_match >= 2) ins_rrpv = 0; // Recurring pattern: MRU

    // Streaming sets: distant insert or bypass
    if (streaming && SHIP_TABLE[sig] < 2)
        ins_rrpv = 3; // Distant insert (or bypass fill if victim was valid)

    // Update RRPV
    RRPV[set][way] = ins_rrpv;

    // Set-dueling PSEL update
    if (srrip_leader) {
        if (hit && PSEL < 1023) PSEL++;
        else if (!hit && PSEL > 0) PSEL--;
    }
    if (brrip_leader) {
        if (hit && PSEL > 0) PSEL--;
        else if (!hit && PSEL < 1023) PSEL++;
    }
}

// --- Stats ---
void PrintStats() {
    std::cout << "SASAR stats: PSEL=" << PSEL << std::endl;
}

void PrintStats_Heartbeat() {
    // Optional: print streaming set counts, SHiP stats
}