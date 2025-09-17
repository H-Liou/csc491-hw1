#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- SHiP-lite Metadata ---
// 6-bit PC signature per block
static uint8_t block_signature[LLC_SETS][LLC_WAYS]; // 6 bits per block

// 2-bit outcome counter per signature (table size: 2048 entries)
static uint8_t signature_outcome[2048]; // 2 bits per signature

// --- DRRIP Metadata ---
// 2-bit RRPV per block
static uint8_t rrpv[LLC_SETS][LLC_WAYS];

// 10-bit PSEL counter for set-dueling
static uint16_t PSEL = 512; // Range: 0–1023

// 64 leader sets for SRRIP, 64 for BRRIP
#define NUM_LEADER_SETS 64
static uint8_t is_leader_srrip[LLC_SETS];
static uint8_t is_leader_brrip[LLC_SETS];

// Helper: hash PC to 6-bit signature
inline uint8_t GetSignature(uint64_t PC) {
    return (PC ^ (PC >> 6) ^ (PC >> 12)) & 0x3F;
}

// Helper: hash signature to outcome table index (11 bits)
inline uint16_t SigIdx(uint8_t sig) {
    return sig; // direct mapping for 64 entries, or (sig ^ (sig << 3)) & 0x7FF for 2048
}

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv));
    memset(block_signature, 0, sizeof(block_signature));
    memset(signature_outcome, 1, sizeof(signature_outcome)); // weak reuse by default
    memset(is_leader_srrip, 0, sizeof(is_leader_srrip));
    memset(is_leader_brrip, 0, sizeof(is_leader_brrip));
    // Assign leader sets: first 64 for SRRIP, next 64 for BRRIP
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i)
        is_leader_srrip[i] = 1;
    for (uint32_t i = NUM_LEADER_SETS; i < 2 * NUM_LEADER_SETS; ++i)
        is_leader_brrip[i] = 1;
}

// --- Find victim: standard RRIP ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Find block with RRPV==3
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        // Aging: increment all RRPVs < 3
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
    // --- SHiP signature ---
    uint8_t sig = GetSignature(PC);
    uint16_t sig_idx = SigIdx(sig);

    // On hit: promote to MRU, update outcome counter
    if (hit) {
        rrpv[set][way] = 0;
        if (signature_outcome[sig_idx] < 3)
            ++signature_outcome[sig_idx];
        return;
    }

    // On miss: update outcome counter for victim block
    uint8_t victim_sig = block_signature[set][way];
    uint16_t victim_idx = SigIdx(victim_sig);
    if (signature_outcome[victim_idx] > 0)
        --signature_outcome[victim_idx];

    // --- DRRIP set-dueling: choose insertion policy ---
    bool use_srrip = false;
    if (is_leader_srrip[set])
        use_srrip = true;
    else if (is_leader_brrip[set])
        use_srrip = false;
    else
        use_srrip = (PSEL >= 512);

    // --- SHiP insertion depth ---
    // If signature outcome counter is strong (>=2), insert at RRPV=0 (MRU)
    // Else, use DRRIP policy: SRRIP (RRPV=2) or BRRIP (RRPV=2 with 1/32 probability, else RRPV=3)
    if (signature_outcome[sig_idx] >= 2) {
        rrpv[set][way] = 0;
    } else {
        if (use_srrip) {
            rrpv[set][way] = 2;
        } else {
            // BRRIP: insert at RRPV=2 with 1/32 probability, else RRPV=3
            static uint32_t brripep = 0;
            if ((brripep++ & 0x1F) == 0)
                rrpv[set][way] = 2;
            else
                rrpv[set][way] = 3;
        }
    }
    // Track signature for inserted block
    block_signature[set][way] = sig;

    // --- Set-dueling: update PSEL ---
    if (is_leader_srrip[set] && hit && PSEL < 1023)
        ++PSEL;
    else if (is_leader_brrip[set] && hit && PSEL > 0)
        --PSEL;
}

// --- Print statistics ---
void PrintStats() {
    uint32_t strong_sig = 0;
    for (uint32_t i = 0; i < 2048; ++i)
        if (signature_outcome[i] >= 2) ++strong_sig;
    std::cout << "SHiP-DRRIP Policy\n";
    std::cout << "Strong reuse signatures: " << strong_sig << " / 2048\n";
    std::cout << "PSEL value: " << PSEL << " (SRRIP if >=512)\n";
}

// --- Heartbeat stats ---
void PrintStats_Heartbeat() {
    // Optional: print periodic signature reuse distribution
}