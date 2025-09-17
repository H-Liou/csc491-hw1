#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- SHiP-lite metadata ---
// 2-bit RRPV per line
uint8_t rrpv[LLC_SETS][LLC_WAYS];
// 6-bit PC signature per line
uint8_t pc_sig[LLC_SETS][LLC_WAYS];

// --- Signature outcome table: 4K entries, 2-bit counters ---
#define SIG_TABLE_SIZE 4096
uint8_t sig_table[SIG_TABLE_SIZE];

// --- Streaming detector: per-set 1-bit flag, 32-bit last address ---
uint8_t streaming_flag[LLC_SETS];
uint32_t last_addr[LLC_SETS];

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv)); // LRU
    memset(pc_sig, 0, sizeof(pc_sig));
    memset(sig_table, 1, sizeof(sig_table)); // neutral reuse
    memset(streaming_flag, 0, sizeof(streaming_flag));
    memset(last_addr, 0, sizeof(last_addr));
}

// --- Helper: get 6-bit PC signature ---
inline uint16_t get_signature(uint64_t PC) {
    // Use lower 6 bits of CRC32 hash of PC for better mixing
    return champsim_crc32(PC) & 0x3F;
}

// --- Helper: signature table index ---
inline uint16_t sig_index(uint16_t sig) {
    // 4K-entry table: use signature as index, optionally add set bits for more diversity
    return sig;
}

// --- Victim selection: standard RRIP ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Streaming phase: prefer to bypass blocks with low-reuse signature
    if (streaming_flag[set]) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            uint16_t sig = pc_sig[set][way];
            if (sig_table[sig_index(sig)] == 0 && rrpv[set][way] == 3)
                return way;
        }
    }
    // Normal RRIP victim selection
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] < 3)
                rrpv[set][way]++;
    }
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
    // --- Streaming detector update (per set) ---
    uint32_t block_addr = (uint32_t)(paddr >> 6); // block address
    uint32_t delta = block_addr - last_addr[set];
    if (last_addr[set] != 0 && (delta == 1 || delta == (uint32_t)-1)) {
        streaming_flag[set] = 1; // monotonic access detected
    } else if (last_addr[set] != 0 && delta != 0) {
        streaming_flag[set] = 0;
    }
    last_addr[set] = block_addr;

    // --- SHiP-lite update ---
    uint16_t sig = get_signature(PC);
    uint16_t idx = sig_index(sig);

    if (hit) {
        // On hit: increment signature counter (max 3), promote to MRU
        if (sig_table[idx] < 3) sig_table[idx]++;
        rrpv[set][way] = 0;
    } else {
        // On miss: decrement signature counter (min 0)
        if (sig_table[idx] > 0) sig_table[idx]--;
        // Insert: choose RRPV based on signature counter
        uint8_t ins_rrpv = 2; // default: mid
        if (sig_table[idx] == 3)
            ins_rrpv = 0; // high reuse: MRU
        else if (sig_table[idx] == 2)
            ins_rrpv = 1; // moderate reuse
        else if (sig_table[idx] == 1)
            ins_rrpv = 2; // neutral
        else
            ins_rrpv = 3; // low reuse: LRU

        // Streaming phase: bypass blocks with low-reuse signature
        if (streaming_flag[set] && sig_table[idx] <= 1)
            ins_rrpv = 3; // insert at LRU

        rrpv[set][way] = ins_rrpv;
        pc_sig[set][way] = sig;
    }
}

// --- Stats ---
void PrintStats() {
    int streaming_sets = 0;
    int high_reuse_sigs = 0, low_reuse_sigs = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (streaming_flag[s]) streaming_sets++;
    for (uint32_t i = 0; i < SIG_TABLE_SIZE; ++i) {
        if (sig_table[i] == 3) high_reuse_sigs++;
        if (sig_table[i] == 0) low_reuse_sigs++;
    }
    std::cout << "SHiP-SA: Streaming sets: " << streaming_sets << " / " << LLC_SETS << std::endl;
    std::cout << "SHiP-SA: High-reuse signatures: " << high_reuse_sigs << " / " << SIG_TABLE_SIZE << std::endl;
    std::cout << "SHiP-SA: Low-reuse signatures: " << low_reuse_sigs << " / " << SIG_TABLE_SIZE << std::endl;
}

void PrintStats_Heartbeat() {
    int streaming_sets = 0;
    for (uint32_t s = 0; s < LLC_SETS; ++s)
        if (streaming_flag[s]) streaming_sets++;
    std::cout << "SHiP-SA: Streaming sets: " << streaming_sets << std::endl;
}