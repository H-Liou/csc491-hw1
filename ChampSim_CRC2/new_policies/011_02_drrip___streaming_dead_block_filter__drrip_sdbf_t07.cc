#include <vector>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- DRRIP metadata ---
static uint8_t rrpv[LLC_SETS][LLC_WAYS];           // 2 bits per line
static uint8_t dbf[LLC_SETS][LLC_WAYS];            // 2 bits per line (dead-block filter, reuse counter)

// --- Streaming detector ---
static uint64_t last_addr[LLC_SETS];
static int64_t last_delta[LLC_SETS];
static uint8_t stream_ctr[LLC_SETS];               // 2 bits per set

// --- DRRIP Set-dueling ---
static uint32_t PSEL = 512;                        // 10-bit policy selector
static bool is_leader_srrip[LLC_SETS];             // 32 leader sets (SRRIP)
static bool is_leader_brrip[LLC_SETS];             // 32 leader sets (BRRIP)

static std::vector<uint32_t> srrip_leader_sets;
static std::vector<uint32_t> brrip_leader_sets;

// --- Initialization ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv));     // long re-use distance
    memset(dbf, 0, sizeof(dbf));       // initially dead
    memset(last_addr, 0, sizeof(last_addr));
    memset(last_delta, 0, sizeof(last_delta));
    memset(stream_ctr, 0, sizeof(stream_ctr));
    memset(is_leader_srrip, 0, sizeof(is_leader_srrip));
    memset(is_leader_brrip, 0, sizeof(is_leader_brrip));
    srrip_leader_sets.clear();
    brrip_leader_sets.clear();

    // Choose 32 SRRIP and 32 BRRIP leader sets
    for (uint32_t i = 0; i < 32; ++i) {
        uint32_t srrip_idx = i * LLC_SETS / 64;
        uint32_t brrip_idx = LLC_SETS / 2 + i * LLC_SETS / 64;
        is_leader_srrip[srrip_idx] = true;
        is_leader_brrip[brrip_idx] = true;
        srrip_leader_sets.push_back(srrip_idx);
        brrip_leader_sets.push_back(brrip_idx);
    }
}

// --- Streaming detector update ---
inline bool IsStreaming(uint32_t set, uint64_t paddr) {
    int64_t delta = paddr - last_addr[set];
    bool streaming = false;
    if (last_delta[set] != 0 && delta == last_delta[set]) {
        if (stream_ctr[set] < 3) ++stream_ctr[set];
    } else {
        if (stream_ctr[set] > 0) --stream_ctr[set];
    }
    streaming = (stream_ctr[set] >= 2);
    last_delta[set] = delta;
    last_addr[set] = paddr;
    return streaming;
}

// --- DRRIP insertion policy ---
inline uint8_t DRRIP_Get_Insert_RRPV(uint32_t set) {
    // Set-dueling: use leader sets for policy selection
    if (is_leader_srrip[set])
        return 2; // SRRIP: insert at RRPV=2
    if (is_leader_brrip[set])
        return (rand() % 32 == 0) ? 2 : 3; // BRRIP: insert at RRPV=2 with 1/32 probability, else RRPV=3

    // Non-leader sets: follow PSEL
    return (PSEL >= 512) ? 2 : ((rand() % 32 == 0) ? 2 : 3);
}

// --- Victim selection (SRRIP) ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] < 3) ++rrpv[set][way];
    }
    return 0;
}

// --- Dead-block filter update (decay every 10K accesses) ---
static uint64_t global_access = 0;
inline void DecayDBF() {
    // Decay (halve) all dbf counters every 10,000 accesses
    if (global_access % 10000 == 0) {
        for (uint32_t set = 0; set < LLC_SETS; ++set)
            for (uint32_t way = 0; way < LLC_WAYS; ++way)
                if (dbf[set][way] > 0) dbf[set][way]--;
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
    global_access++;
    DecayDBF();

    // --- Streaming detection ---
    bool streaming = IsStreaming(set, paddr);

    // --- On hit: promote to MRU, increment dead-block filter ---
    if (hit) {
        rrpv[set][way] = 0;
        if (dbf[set][way] < 3) dbf[set][way]++;
        return;
    }

    // --- Update DRRIP set-dueling statistics ---
    // Only leader sets update PSEL
    if (is_leader_srrip[set]) {
        if (dbf[set][way] > 0) { // Block reused before eviction
            if (PSEL < 1023) ++PSEL;
        } else { // Dead block
            if (PSEL > 0) --PSEL;
        }
    }
    else if (is_leader_brrip[set]) {
        if (dbf[set][way] > 0) { // Block reused before eviction
            if (PSEL > 0) --PSEL;
        } else {
            if (PSEL < 1023) ++PSEL;
        }
    }

    // --- Dead-block filter reset for new block ---
    dbf[set][way] = 0;

    // --- Streaming-aware dead-block bypass ---
    if (streaming && dbf[set][way] == 0) {
        rrpv[set][way] = 3; // Insert at distant RRPV (bypass)
        return;
    }

    // --- Normal DRRIP insertion ---
    rrpv[set][way] = DRRIP_Get_Insert_RRPV(set);
}

// --- Print statistics ---
void PrintStats() {
    std::cout << "DRRIP-SDBF Policy: DRRIP + Streaming-Dead Block Filter\n";
    std::cout << "PSEL value: " << PSEL << std::endl;
    // Streaming counter histogram
    uint32_t stream_hist[4] = {0,0,0,0};
    for (uint32_t i = 0; i < LLC_SETS; ++i)
        stream_hist[stream_ctr[i]]++;
    std::cout << "Streaming counter histogram: ";
    for (int i=0; i<4; ++i) std::cout << stream_hist[i] << " ";
    std::cout << std::endl;
    // Dead-block filter histogram
    uint32_t dbf_hist[4] = {0,0,0,0};
    for (uint32_t set=0; set<LLC_SETS; ++set)
        for (uint32_t way=0; way<LLC_WAYS; ++way)
            dbf_hist[dbf[set][way]]++;
    std::cout << "Dead-block filter histogram: ";
    for (int i=0; i<4; ++i) std::cout << dbf_hist[i] << " ";
    std::cout << std::endl;
}

void PrintStats_Heartbeat() {}