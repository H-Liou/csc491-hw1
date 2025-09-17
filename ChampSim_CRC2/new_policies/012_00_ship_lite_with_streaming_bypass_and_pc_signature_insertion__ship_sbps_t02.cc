#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- SHiP-lite metadata: 6-bit PC signature, 2-bit outcome counter per line ---
uint8_t pc_sig[LLC_SETS][LLC_WAYS];      // 6 bits per line
uint8_t reuse_ctr[LLC_SETS][LLC_WAYS];   // 2 bits per line

// --- Signature table: 64-entry, 2-bit counter per signature ---
#define SIG_TABLE_SIZE 64
uint8_t sig_table[SIG_TABLE_SIZE];       // 2 bits per entry

// --- Streaming detector: per-set 1-bit flag, 32-bit last address ---
uint8_t streaming_flag[LLC_SETS];
uint32_t last_addr[LLC_SETS];

// --- Periodic decay counter ---
uint64_t access_counter = 0;
#define DECAY_PERIOD 100000

// --- Helper: hash PC to 6-bit signature ---
inline uint8_t GetSignature(uint64_t PC) {
    // Simple CRC or bit-mix for 6 bits
    return champsim_crc2(PC, 0) & 0x3F;
}

// --- Initialization ---
void InitReplacementState() {
    memset(pc_sig, 0, sizeof(pc_sig));
    memset(reuse_ctr, 0, sizeof(reuse_ctr));
    memset(sig_table, 1, sizeof(sig_table)); // Start neutral
    memset(streaming_flag, 0, sizeof(streaming_flag));
    memset(last_addr, 0, sizeof(last_addr));
    access_counter = 0;
}

// --- Victim selection: RRIP-style, prefer lines with low reuse_ctr ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Streaming phase: bypass cache if detected
    if (streaming_flag[set]) {
        // Find block with lowest reuse_ctr (prefer eviction of dead blocks)
        uint32_t victim = 0;
        uint8_t min_reuse = 3;
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (reuse_ctr[set][way] <= min_reuse) {
                min_reuse = reuse_ctr[set][way];
                victim = way;
            }
        }
        return victim;
    }

    // Normal: RRIP-style, but bias toward lines with low reuse_ctr
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (reuse_ctr[set][way] == 0)
            return way;
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (reuse_ctr[set][way] == 1)
            return way;
    // Otherwise, evict LRU (way 0)
    return 0;
}

// --- Replacement state update ---
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
    access_counter++;

    // --- Streaming detector update (per set) ---
    uint32_t block_addr = (uint32_t)(paddr >> 6); // block address
    uint32_t delta = block_addr - last_addr[set];
    if (last_addr[set] != 0 && (delta == 1 || delta == (uint32_t)-1)) {
        streaming_flag[set] = 1; // monotonic access detected
    } else if (last_addr[set] != 0 && delta != 0) {
        streaming_flag[set] = 0;
    }
    last_addr[set] = block_addr;

    // --- PC signature ---
    uint8_t sig = GetSignature(PC);

    // --- Signature table update ---
    if (hit) {
        if (sig_table[sig] < 3) sig_table[sig]++;
    } else {
        if (sig_table[sig] > 0) sig_table[sig]--;
    }

    // --- Per-line metadata update ---
    pc_sig[set][way] = sig;
    reuse_ctr[set][way] = hit ? 3 : sig_table[sig];

    // --- Periodic decay of reuse counters ---
    if (access_counter % DECAY_PERIOD == 0) {
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            for (uint32_t w = 0; w < LLC_WAYS; ++w)
                if (reuse_ctr[s][w] > 0)
                    reuse_ctr[s][w]--;
        for (uint32_t i = 0; i < SIG_TABLE_SIZE; ++i)
            if (sig_table[i] > 0)
                sig_table[i]--;
    }
}

// --- Stats ---
void PrintStats() {
    int streaming_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (streaming_flag[s]) streaming_sets++;
    std::cout << "SHiP-SBPS: Streaming sets: " << streaming_sets << " / " << LLC_SETS << std::endl;

    int dead_blocks = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        for (uint32_t w = 0; w < LLC_WAYS; ++w)
            if (reuse_ctr[s][w] == 0) dead_blocks++;
    std::cout << "SHiP-SBPS: Dead blocks: " << dead_blocks << " / " << (LLC_SETS * LLC_WAYS) << std::endl;

    int high_reuse = 0;
    for (uint32_t i = 0; i < SIG_TABLE_SIZE; ++i)
        if (sig_table[i] == 3) high_reuse++;
    std::cout << "SHiP-SBPS: High-reuse signatures: " << high_reuse << " / " << SIG_TABLE_SIZE << std::endl;
}

void PrintStats_Heartbeat() {
    int streaming_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (streaming_flag[s]) streaming_sets++;
    std::cout << "SHiP-SBPS: Streaming sets: " << streaming_sets << std::endl;
}