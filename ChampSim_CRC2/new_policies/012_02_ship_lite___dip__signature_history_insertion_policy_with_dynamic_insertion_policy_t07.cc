#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- SHiP-Lite: PC signature per line and global table ---
static uint8_t rrpv[LLC_SETS][LLC_WAYS];           // 2 bits per line
static uint8_t pc_sig[LLC_SETS][LLC_WAYS];         // 6 bits per line
static const uint32_t SIG_TABLE_SIZE = 4096;       // 4K entries
static uint8_t sig_table[SIG_TABLE_SIZE];          // 2 bits per signature

// --- DIP set-dueling ---
static const uint32_t NUM_LEADER_SETS = 32;
static uint32_t lip_leader_sets[NUM_LEADER_SETS];
static uint32_t bip_leader_sets[NUM_LEADER_SETS];
static uint16_t psel = 512;                        // 10-bit PSEL

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv));     // All lines: RRPV=3 (long re-use)
    memset(pc_sig, 0, sizeof(pc_sig));
    memset(sig_table, 1, sizeof(sig_table));  // Default: low reuse

    psel = 512;
    // Fixed leader set selection for reproducibility
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i) {
        lip_leader_sets[i] = (i * 17) % LLC_SETS;
        bip_leader_sets[i] = ((i * 17) + 7) % LLC_SETS;
    }
}

// --- PC signature hash (6 bits from PC) ---
inline uint16_t GetSignature(uint64_t PC) {
    // Use simple CRC or XOR folding for 6 bits
    return (champsim_crc2(PC) ^ (PC >> 6)) & 0x3F;
}

// --- Signature table index ---
inline uint32_t SigTableIdx(uint16_t sig) {
    // Direct-mapped, 4K-entry table
    return sig & (SIG_TABLE_SIZE - 1);
}

// --- DIP leader set policy selection ---
inline bool UseLIP(uint32_t set) {
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i) {
        if (set == lip_leader_sets[i]) return true;
        if (set == bip_leader_sets[i]) return false;
    }
    return (psel < 512); // LIP if PSEL < midpoint
}

// --- Find victim (SRRIP) ---
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
            if (rrpv[set][way] < 3) ++rrpv[set][way];
    }
    return 0;
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
    // --- Extract signature ---
    uint16_t sig = GetSignature(PC);
    uint32_t sig_idx = SigTableIdx(sig);

    // --- On hit: promote to MRU, update signature table ---
    if (hit) {
        rrpv[set][way] = 0;
        // Mark signature as reused (increment saturating counter)
        if (sig_table[sig_idx] < 3)
            sig_table[sig_idx]++;
        return;
    }

    // --- On eviction: update signature table ---
    uint8_t evicted_sig = pc_sig[set][way];
    uint32_t evicted_idx = SigTableIdx(evicted_sig);
    // If block was not reused, decrement counter
    if (sig_table[evicted_idx] > 0)
        sig_table[evicted_idx]--;

    // --- DIP set-dueling update ---
    bool is_lip_leader = false, is_bip_leader = false;
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i) {
        if (set == lip_leader_sets[i]) is_lip_leader = true;
        if (set == bip_leader_sets[i]) is_bip_leader = true;
    }
    if (is_lip_leader && hit) {
        if (psel < 1023) psel++;
    }
    if (is_bip_leader && hit) {
        if (psel > 0) psel--;
    }

    // --- Insert new block: SHiP-guided insertion depth ---
    pc_sig[set][way] = sig; // Save signature for future eviction

    if (sig_table[sig_idx] >= 2) {
        // Good reuse signature: insert at MRU (RRPV=0)
        rrpv[set][way] = 0;
    } else if (sig_table[sig_idx] == 1) {
        // Moderate reuse: insert at RRPV=2
        rrpv[set][way] = 2;
    } else {
        // Low/no reuse: use DIP global policy (LIP/BIP)
        // LIP: always insert at RRPV=3 (long re-use)
        // BIP: insert at MRU (RRPV=0) with low probability, else RRPV=3
        bool use_lip = UseLIP(set);
        if (use_lip) {
            rrpv[set][way] = 3;
        } else {
            if ((rand() & 0x1F) == 0) // ~1/32 MRU
                rrpv[set][way] = 0;
            else
                rrpv[set][way] = 3;
        }
    }
}

// --- Print statistics ---
void PrintStats() {
    std::cout << "SHiP-Lite + DIP Policy\n";
    std::cout << "PSEL value: " << psel << std::endl;
    // Signature table reuse histogram
    uint32_t sig_hist[4] = {0,0,0,0};
    for (uint32_t i=0; i<SIG_TABLE_SIZE; ++i)
        sig_hist[sig_table[i]]++;
    std::cout << "Signature table reuse histogram: ";
    for (int i=0; i<4; ++i) std::cout << sig_hist[i] << " ";
    std::cout << std::endl;
}

void PrintStats_Heartbeat() {}