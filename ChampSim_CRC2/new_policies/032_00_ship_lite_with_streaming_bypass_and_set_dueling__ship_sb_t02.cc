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

// ---- SHiP-lite: per-line PC signature (6 bits) ----
uint8_t pc_sig[LLC_SETS][LLC_WAYS]; // 6 bits per block

// ---- SHiP outcome table: 4096 entries, 2 bits each ----
#define SHIP_ENTRIES 4096
uint8_t ship_ctr[SHIP_ENTRIES]; // 2 bits per entry

// ---- Streaming detector: per-set monotonicity ----
uint64_t last_addr[LLC_SETS]; // 48 bits per set (paddr)
uint8_t stream_score[LLC_SETS]; // 2 bits per set

// ---- Set-dueling: 64 leader sets for SRRIP, 64 for BRRIP ----
#define NUM_LEADER_SETS 64
uint8_t is_srrip_leader[LLC_SETS];
uint8_t is_brrip_leader[LLC_SETS];

// ---- PSEL counter: 10 bits ----
uint16_t psel = 512; // 0..1023, SRRIP if psel >= 512, else BRRIP

// ---- Other bookkeeping ----
uint64_t access_counter = 0;
#define DECAY_PERIOD 100000

// Helper: hash PC to 6 bits
inline uint16_t get_pc_sig(uint64_t PC) {
    return (PC ^ (PC >> 6) ^ (PC >> 12)) & 0x3F; // 6 bits
}

// Helper: hash PC to SHiP table index (12 bits)
inline uint16_t get_ship_idx(uint64_t PC) {
    return (PC ^ (PC >> 13) ^ (PC >> 23)) & 0xFFF; // 12 bits
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
        last_addr[set] = 0;
        stream_score[set] = 0;
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

    // ---- Streaming detector ----
    uint64_t last = last_addr[set];
    uint8_t score = stream_score[set];
    if (last == 0) {
        last_addr[set] = paddr;
        stream_score[set] = 0;
    } else {
        uint64_t delta = (paddr > last) ? (paddr - last) : (last - paddr);
        if (delta == 64 || delta == 128) { // 1-2 block stride
            if (score < 3) stream_score[set]++;
        } else {
            if (score > 0) stream_score[set]--;
        }
        last_addr[set] = paddr;
    }
    bool streaming = (stream_score[set] >= 2);

    // ---- SHiP signature and outcome update ----
    uint16_t sig = get_pc_sig(PC);
    uint16_t ship_idx = get_ship_idx(PC);

    if (hit) {
        // On hit, increase reuse confidence for signature
        if (ship_ctr[ship_idx] < 3)
            ship_ctr[ship_idx]++;
        rrpv[set][way] = 0; // promote to MRU
    } else {
        // On miss, decrease reuse confidence
        if (ship_ctr[ship_idx] > 0)
            ship_ctr[ship_idx]--;
    }
    pc_sig[set][way] = sig;

    // ---- Set-dueling: determine insertion policy ----
    bool use_srrip = true;
    if (is_srrip_leader[set])
        use_srrip = true;
    else if (is_brrip_leader[set])
        use_srrip = false;
    else
        use_srrip = (psel >= 512);

    // ---- Insertion policy ----
    if (streaming) {
        // Streaming detected: bypass (set RRPV=3)
        rrpv[set][way] = 3;
    } else {
        // SHiP outcome: insert at MRU if high reuse, else at distant RRPV
        if (ship_ctr[ship_idx] >= 2) {
            rrpv[set][way] = 0; // high reuse, insert at MRU
        } else {
            // SRRIP: insert at RRPV=2; BRRIP: insert at RRPV=2 with 1/32 probability, else RRPV=3
            if (use_srrip) {
                rrpv[set][way] = 2;
            } else {
                if ((access_counter & 0x1F) == 0)
                    rrpv[set][way] = 2;
                else
                    rrpv[set][way] = 3;
            }
        }
    }

    // ---- Set-dueling: update PSEL on leader sets ----
    if (is_srrip_leader[set]) {
        if (hit && !streaming && ship_ctr[ship_idx] < 2 && rrpv[set][way] == 2) {
            // SRRIP leader: reward if hit on distant insertion
            if (psel < 1023) psel++;
        }
    } else if (is_brrip_leader[set]) {
        if (hit && !streaming && ship_ctr[ship_idx] < 2 && (rrpv[set][way] == 2 || rrpv[set][way] == 3)) {
            // BRRIP leader: reward if hit on BRRIP insertion
            if (psel > 0) psel--;
        }
    }

    // ---- Periodic decay of SHiP outcome counters ----
    if (access_counter % DECAY_PERIOD == 0) {
        for (uint32_t i = 0; i < SHIP_ENTRIES; ++i)
            if (ship_ctr[i] > 0)
                ship_ctr[i]--;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    int high_reuse_sigs = 0;
    for (uint32_t i = 0; i < SHIP_ENTRIES; ++i)
        if (ship_ctr[i] >= 2) high_reuse_sigs++;
    int streaming_sets = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        if (stream_score[set] >= 2) streaming_sets++;
    std::cout << "SHiP-SB Policy: SHiP-Lite + Streaming Bypass + Set-Dueling" << std::endl;
    std::cout << "High-reuse signatures: " << high_reuse_sigs << "/" << SHIP_ENTRIES << std::endl;
    std::cout << "Streaming sets (score>=2): " << streaming_sets << "/" << LLC_SETS << std::endl;
    std::cout << "PSEL value: " << psel << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    int high_reuse_sigs = 0;
    for (uint32_t i = 0; i < SHIP_ENTRIES; ++i)
        if (ship_ctr[i] >= 2) high_reuse_sigs++;
    int streaming_sets = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        if (stream_score[set] >= 2) streaming_sets++;
    std::cout << "High-reuse signatures (heartbeat): " << high_reuse_sigs << "/" << SHIP_ENTRIES << std::endl;
    std::cout << "Streaming sets (heartbeat): " << streaming_sets << "/" << LLC_SETS << std::endl;
    std::cout << "PSEL value (heartbeat): " << psel << std::endl;
}