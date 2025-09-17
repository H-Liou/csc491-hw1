#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- Per-block metadata ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];         // 2 bits per block
uint8_t pc_sig[LLC_SETS][LLC_WAYS];       // 5 bits per block (signature)
                                          // (total: 2048*16*7 = ~224 KiB bits = ~28 KiB bytes)
                                          
// --- SHiP outcome counters ---
#define SHIP_SIG_BITS 5
#define SHIP_SIG_ENTRIES (1 << SHIP_SIG_BITS)
uint8_t ship_outcome[SHIP_SIG_ENTRIES];   // 2 bits per entry (reuse counter)

// --- Streaming detector ---
uint8_t streaming_flag[LLC_SETS];         // 2 bits per set (0: none, 1: streaming up, 2: streaming down)

// Helper: hash PC to signature
inline uint8_t GetSig(uint64_t PC) {
    // Simple hash, fits 5 bits
    return (PC ^ (PC >> 5) ^ (PC >> 11)) & ((1 << SHIP_SIG_BITS) - 1);
}

// Helper: detect streaming access pattern in a set
struct StreamDetect {
    uint64_t last_addr[LLC_SETS];
    int64_t last_delta[LLC_SETS];
    uint8_t streak[LLC_SETS]; // up to 7
    void Init() {
        memset(last_addr, 0, sizeof(last_addr));
        memset(last_delta, 0, sizeof(last_delta));
        memset(streak, 0, sizeof(streak));
    }
    // Call on every access; returns true if streaming detected
    bool Update(uint32_t set, uint64_t addr) {
        int64_t delta = addr - last_addr[set];
        if (delta != 0 && delta == last_delta[set]) {
            if (streak[set] < 7) streak[set]++;
        } else {
            streak[set] = 0;
        }
        last_delta[set] = delta;
        last_addr[set] = addr;

        if (streak[set] >= 5) {
            streaming_flag[set] = (delta > 0) ? 1 : 2;
            return true;
        } else {
            streaming_flag[set] = 0;
            return false;
        }
    }
    bool IsStreaming(uint32_t set) {
        return streaming_flag[set] != 0;
    }
} stream_detect;

// Initialize replacement state
void InitReplacementState() {
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            rrpv[set][way] = 2;      // distant
            pc_sig[set][way] = 0;
        }
        streaming_flag[set] = 0;
    }
    for (uint32_t i = 0; i < SHIP_SIG_ENTRIES; ++i)
        ship_outcome[i] = 1; // neutral
    stream_detect.Init();
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
    // Prefer invalid block
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (!current_set[way].valid)
            return way;
    // Classic RRIP victim selection
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] < 3)
                rrpv[set][way]++;
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
    stream_detect.Update(set, paddr);

    // --- SHiP signature outcome update ---
    uint8_t sig = GetSig(PC);

    if (hit) {
        // Block reused: increment outcome (max 3)
        if (ship_outcome[sig] < 3) ship_outcome[sig]++;
        rrpv[set][way] = 0; // protect
    } else {
        // Block not reused: decrement outcome (min 0)
        if (ship_outcome[sig] > 0) ship_outcome[sig]--;
    }

    // --- Block signature update ---
    pc_sig[set][way] = sig;

    // --- Insertion policy ---
    if (!hit) {
        // Streaming detected: insert at RRPV=3 (very distant)
        if (stream_detect.IsStreaming(set)) {
            rrpv[set][way] = 3;
        } else {
            // SHiP-style: use outcome to bias insertion depth
            if (ship_outcome[sig] >= 2)
                rrpv[set][way] = 0; // protect hot signature
            else
                rrpv[set][way] = 2; // distant for cold signature
        }
        // Optionally: bypass if streaming and all blocks valid (conservative, rare)
        // But for safety, just insert at RRPV=3 to avoid starvation
    }

    // --- Periodic decay of SHiP outcomes ---
    static uint64_t access_count = 0;
    access_count++;
    if (access_count % (LLC_SETS * LLC_WAYS * 8) == 0) { // every ~256k accesses
        for (uint32_t i = 0; i < SHIP_SIG_ENTRIES; ++i)
            if (ship_outcome[i] > 0) ship_outcome[i]--;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    int hot_blocks = 0, cold_blocks = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            uint8_t sig = pc_sig[set][way];
            if (ship_outcome[sig] >= 2) hot_blocks++;
            else cold_blocks++;
        }
    }
    int streaming_sets = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        if (streaming_flag[set]) streaming_sets++;
    std::cout << "SHiP-lite + Streaming Detector Hybrid Policy" << std::endl;
    std::cout << "Hot blocks: " << hot_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "Streaming sets: " << streaming_sets << "/" << LLC_SETS << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    int hot_blocks = 0, streaming_sets = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            uint8_t sig = pc_sig[set][way];
            if (ship_outcome[sig] >= 2) hot_blocks++;
        }
        if (streaming_flag[set]) streaming_sets++;
    }
    std::cout << "Hot blocks (heartbeat): " << hot_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "Streaming sets (heartbeat): " << streaming_sets << "/" << LLC_SETS << std::endl;
}