#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// ---- RRIP Metadata ----
uint8_t rrpv[LLC_SETS][LLC_WAYS]; // 2 bits per block

// ---- SHiP-lite: per-line PC signature (4 bits) ----
uint8_t pc_sig[LLC_SETS][LLC_WAYS]; // 4 bits per block

// ---- SHiP outcome table: 2048 entries, 2 bits each ----
#define SHIP_ENTRIES 2048
uint8_t ship_ctr[SHIP_ENTRIES]; // 2 bits per entry

// ---- DRRIP set-dueling: 64 leader sets for SRRIP, 64 for BRRIP ----
#define NUM_LEADER_SETS 64
uint8_t is_srrip_leader[LLC_SETS];
uint8_t is_brrip_leader[LLC_SETS];

// ---- PSEL counter: 10 bits ----
uint16_t psel = 512; // 0..1023, SRRIP if psel >= 512, else BRRIP

// ---- Streaming detector: per set, 8 bits ----
uint8_t stream_score[LLC_SETS]; // 8 bits per set
uint64_t last_addr[LLC_SETS];   // last paddr per set

// ---- Other bookkeeping ----
uint64_t access_counter = 0;
#define DECAY_PERIOD 100000

// Helper: hash PC to 4 bits
inline uint8_t get_pc_sig(uint64_t PC) {
    return (PC ^ (PC >> 4) ^ (PC >> 12)) & 0xF; // 4 bits
}

// Helper: hash PC to SHiP table index (11 bits)
inline uint16_t get_ship_idx(uint64_t PC) {
    return (PC ^ (PC >> 11) ^ (PC >> 21)) & 0x7FF; // 11 bits
}

// Helper: assign leader sets for set-dueling
void assign_leader_sets() {
    memset(is_srrip_leader, 0, sizeof(is_srrip_leader));
    memset(is_brrip_leader, 0, sizeof(is_brrip_leader));
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i) {
        is_srrip_leader[i] = 1;
        is_brrip_leader[LLC_SETS - 1 - i] = 1;
    }
}

void InitReplacementState() {
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            rrpv[set][way] = 3;
            pc_sig[set][way] = 0;
        }
        stream_score[set] = 0;
        last_addr[set] = 0;
    }
    for (uint32_t i = 0; i < SHIP_ENTRIES; ++i)
        ship_ctr[i] = 1; // weakly dead
    assign_leader_sets();
    psel = 512;
    access_counter = 0;
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

    // RRIP: select block with max RRPV (3)
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
    access_counter++;

    // ---- SHiP signature and outcome update ----
    uint8_t sig = get_pc_sig(PC);
    uint16_t ship_idx = get_ship_idx(PC);

    if (hit) {
        if (ship_ctr[ship_idx] < 3)
            ship_ctr[ship_idx]++;
        rrpv[set][way] = 0; // promote to MRU
    } else {
        if (ship_ctr[ship_idx] > 0)
            ship_ctr[ship_idx]--;
    }
    pc_sig[set][way] = sig;

    // ---- Streaming detector ----
    uint64_t delta = (last_addr[set] > 0) ? std::abs((int64_t)paddr - (int64_t)last_addr[set]) : 0;
    last_addr[set] = paddr;

    // Streaming if delta is near-monotonic (>=64 and <=1024)
    if (delta >= 64 && delta <= 1024)
        if (stream_score[set] < 255) stream_score[set]++;
    else
        if (stream_score[set] > 0) stream_score[set]--;

    bool streaming = (stream_score[set] >= 32);

    // ---- DRRIP set-dueling: determine insertion policy ----
    bool use_srrip = true;
    if (is_srrip_leader[set])
        use_srrip = true;
    else if (is_brrip_leader[set])
        use_srrip = false;
    else
        use_srrip = (psel >= 512);

    // ---- Final insertion depth logic ----
    if (streaming) {
        // Streaming detected: bypass/insert at distant RRPV
        rrpv[set][way] = 3;
    } else if (ship_ctr[ship_idx] >= 2) {
        // High reuse: insert at MRU
        rrpv[set][way] = 0;
    } else {
        // DRRIP insertion: SRRIP=2, BRRIP=3 with 1/32 probability
        if (use_srrip) {
            rrpv[set][way] = 2;
        } else {
            if ((access_counter & 0x1F) == 0)
                rrpv[set][way] = 3;
            else
                rrpv[set][way] = 2;
        }
    }

    // ---- Set-dueling: update PSEL on leader sets ----
    if (is_srrip_leader[set]) {
        if (hit) {
            if (psel < 1023) psel++;
        }
    } else if (is_brrip_leader[set]) {
        if (hit) {
            if (psel > 0) psel--;
        }
    }

    // ---- Periodic decay ----
    if (access_counter % DECAY_PERIOD == 0) {
        for (uint32_t i = 0; i < SHIP_ENTRIES; ++i)
            if (ship_ctr[i] > 0)
                ship_ctr[i]--;
        for (uint32_t set = 0; set < LLC_SETS; ++set)
            if (stream_score[set] > 0)
                stream_score[set] /= 2;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    int high_reuse_sigs = 0;
    for (uint32_t i = 0; i < SHIP_ENTRIES; ++i)
        if (ship_ctr[i] >= 2) high_reuse_sigs++;
    int stream_sets = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        if (stream_score[set] >= 32) stream_sets++;
    std::cout << "SBS-Combo Policy: SRRIP-BRRI set-dueling + Streaming Detector + SHiP-Lite\n";
    std::cout << "High-reuse signatures: " << high_reuse_sigs << "/" << SHIP_ENTRIES << std::endl;
    std::cout << "Streaming sets: " << stream_sets << "/" << LLC_SETS << std::endl;
    std::cout << "PSEL value: " << psel << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    int high_reuse_sigs = 0;
    for (uint32_t i = 0; i < SHIP_ENTRIES; ++i)
        if (ship_ctr[i] >= 2) high_reuse_sigs++;
    int stream_sets = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        if (stream_score[set] >= 32) stream_sets++;
    std::cout << "High-reuse signatures (heartbeat): " << high_reuse_sigs << "/" << SHIP_ENTRIES << std::endl;
    std::cout << "Streaming sets (heartbeat): " << stream_sets << "/" << LLC_SETS << std::endl;
    std::cout << "PSEL value (heartbeat): " << psel << std::endl;
}