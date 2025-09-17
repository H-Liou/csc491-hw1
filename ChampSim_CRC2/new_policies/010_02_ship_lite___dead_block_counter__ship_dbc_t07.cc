#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- Metadata sizes ---
#define SHIP_SIG_BITS 6         // 6 bits per PC signature
#define SHIP_NUM_SIG (1 << SHIP_SIG_BITS)
#define DEADCTR_BITS 2          // 2-bit dead-block counter per line
#define PSEL_BITS 10
#define PSEL_MAX ((1 << PSEL_BITS) - 1)
#define PSEL_INIT (PSEL_MAX / 2)
#define NUM_LEADER_SETS 64
#define NUM_SHIP_OUTCOME SHIP_NUM_SIG

// --- Replacement metadata ---
static uint8_t rrpv[LLC_SETS][LLC_WAYS];             // 2 bits per line
static uint8_t ship_sig[LLC_SETS][LLC_WAYS];         // 6 bits per line
static uint8_t deadctr[LLC_SETS][LLC_WAYS];          // 2 bits per line

static uint8_t ship_outcome[NUM_SHIP_OUTCOME];       // 2 bits per signature (SHiP counter)
static uint16_t PSEL;                                // 10 bits global
static uint8_t leader_type[LLC_SETS];                // 0=SRRIP, 1=BRRIP, 2=Follower

// --- Leader set assignment ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv));
    memset(ship_sig, 0, sizeof(ship_sig));
    memset(deadctr, 0, sizeof(deadctr));
    memset(ship_outcome, 0, sizeof(ship_outcome));
    PSEL = PSEL_INIT;
    memset(leader_type, 2, sizeof(leader_type)); // default: Follower

    // Assign leader sets: half SRRIP, half BRRIP
    for (uint32_t i = 0; i < NUM_LEADER_SETS / 2; ++i)
        leader_type[i] = 0; // SRRIP
    for (uint32_t i = NUM_LEADER_SETS / 2; i < NUM_LEADER_SETS; ++i)
        leader_type[i] = 1; // BRRIP
}

// --- SHiP Signature calculation ---
inline uint8_t GetSignature(uint64_t PC) {
    // CRC or simple hash
    return (PC ^ (PC >> 6)) & (SHIP_NUM_SIG - 1);
}

// --- Dead-block bypass logic ---
inline bool ShouldBypass(uint32_t set, uint32_t way) {
    // Bypass if deadctr saturated (i.e., last 3 evicts were dead)
    return (deadctr[set][way] >= 3);
}

// --- Victim selection: SRRIP ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Find RRPV=3 (LRU), prefer those marked dead
    for (uint32_t round = 0; round < 2; ++round) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (rrpv[set][way] == 3) {
                if (round == 1 || ShouldBypass(set, way))
                    return way;
            }
        }
        // If no victim, increment all RRPVs
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] < 3) ++rrpv[set][way];
    }
    // Fallback: first way
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
    uint8_t sig = GetSignature(PC);

    // --- Dead-block tracker update ---
    if (!hit) {
        // If block evicted without reuse, increment deadctr (max 3)
        if (deadctr[set][way] < 3) ++deadctr[set][way];
    } else {
        // Reset on hit
        deadctr[set][way] = 0;
    }

    // --- SHiP outcome table update ---
    if (hit) {
        if (ship_outcome[sig] < 3) ++ship_outcome[sig];
    } else {
        if (ship_outcome[sig] > 0) --ship_outcome[sig];
    }

    // --- Set SHiP signature for new fill ---
    ship_sig[set][way] = sig;

    // --- Insertion Policy selection ---
    uint8_t ins_rrpv = 2; // default: SRRIP insert at 2
    bool leader = (set < NUM_LEADER_SETS);
    bool use_srrip = false;
    if (leader) {
        use_srrip = (leader_type[set] == 0);
    } else {
        use_srrip = (PSEL >= (PSEL_MAX / 2));
    }

    // --- SHiP-guided insertion ---
    if (!hit) {
        // If SHiP outcome counter high (>=2), insert at MRU
        if (ship_outcome[sig] >= 2)
            ins_rrpv = 0;
        else
            ins_rrpv = use_srrip ? 2 : 3; // SRRIP/BRRIP fallback
    } else {
        // On hit, always promote to MRU
        ins_rrpv = 0;
    }

    // --- Dead-block bypass: force distant insert if deadctr saturated ---
    if (!hit && deadctr[set][way] >= 3)
        ins_rrpv = 3;

    rrpv[set][way] = ins_rrpv;

    // --- Adjust PSEL on leader sets ---
    if (leader) {
        if (leader_type[set] == 0) { // SRRIP leader
            if (hit && PSEL < PSEL_MAX) ++PSEL;
            else if (!hit && PSEL > 0) --PSEL;
        } else { // BRRIP leader
            if (hit && PSEL > 0) --PSEL;
            else if (!hit && PSEL < PSEL_MAX) ++PSEL;
        }
    }
}

// --- Print statistics ---
void PrintStats() {
    std::cout << "SHiP-Lite + Dead-Block Counter (SHiP-DBC) Policy\n";
    std::cout << "PSEL value: " << PSEL << " (SRRIP preferred if >= " << (PSEL_MAX / 2) << ")\n";
    uint32_t deadblock_hist[4] = {0,0,0,0};
    for (uint32_t set=0; set<LLC_SETS; ++set)
        for (uint32_t way=0; way<LLC_WAYS; ++way)
            deadblock_hist[deadctr[set][way]]++;
    std::cout << "Dead-block counter histogram: ";
    for (int i=0; i<4; ++i) std::cout << deadblock_hist[i] << " ";
    std::cout << std::endl;

    // SHiP outcome distribution
    uint32_t ship_hist[4] = {0,0,0,0};
    for (uint32_t i=0; i<NUM_SHIP_OUTCOME; ++i)
        ship_hist[ship_outcome[i]]++;
    std::cout << "SHiP outcome histogram: ";
    for (int i=0; i<4; ++i) std::cout << ship_hist[i] << " ";
    std::cout << std::endl;
}

void PrintStats_Heartbeat() {}