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

// ---- SHiP-lite: Signature table ----
#define SHIP_SIG_BITS 6
#define SHIP_TABLE_SIZE 1024 // 6 bits, 1024 entries
struct SHIPEntry {
    uint8_t reuse_counter; // 2 bits
};
SHIPEntry ship_table[SHIP_TABLE_SIZE];

// ---- Per-line PC signatures ----
uint16_t line_sig[LLC_SETS][LLC_WAYS]; // 6 bits per line

// ---- Streaming detector: per-set monotonicity ----
uint64_t last_addr[LLC_SETS]; // 48 bits per set (paddr)
uint8_t stream_score[LLC_SETS]; // 2 bits per set

// ---- DIP Set-dueling: LIP/BIP ----
#define LEADER_SETS 64
uint8_t leader_flags[LLC_SETS]; // 0: normal, 1: LIP leader, 2: BIP leader
uint16_t psel; // 10 bits (0..1023)

// ---- Other bookkeeping ----
uint64_t access_counter = 0;
#define DECAY_PERIOD 100000

void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv));
    memset(ship_table, 1, sizeof(ship_table));
    memset(line_sig, 0, sizeof(line_sig));
    memset(leader_flags, 0, sizeof(leader_flags));
    memset(last_addr, 0, sizeof(last_addr));
    memset(stream_score, 0, sizeof(stream_score));
    access_counter = 0;

    // Assign leader sets: evenly spaced, first 32 LIP, next 32 BIP
    for (uint32_t i = 0; i < LEADER_SETS; ++i) {
        uint32_t lip_set = (i * (LLC_SETS / (2 * LEADER_SETS)));
        uint32_t bip_set = lip_set + (LLC_SETS / 2);
        leader_flags[lip_set] = 1; // LIP leader
        leader_flags[bip_set] = 2; // BIP leader
    }
    psel = 512; // midpoint
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

    // ---- SHiP signature extraction ----
    uint16_t sig = (uint16_t)((PC >> 2) & 0x3F); // 6 bits
    uint16_t ship_idx = sig;
    line_sig[set][way] = sig;

    // ---- SHiP outcome update ----
    if (hit) {
        // Promote block and increment SHiP counter
        rrpv[set][way] = 0;
        if (ship_table[ship_idx].reuse_counter < 3)
            ship_table[ship_idx].reuse_counter++;
    } else {
        // Penalize previous signature
        uint16_t evict_sig = line_sig[set][way];
        if (ship_table[evict_sig].reuse_counter > 0)
            ship_table[evict_sig].reuse_counter--;
    }

    // ---- DIP insertion depth selection ----
    uint8_t leader = leader_flags[set];
    bool use_bip = false;
    if (leader == 1) // LIP leader
        use_bip = false;
    else if (leader == 2) // BIP leader
        use_bip = true;
    else // follower sets
        use_bip = (psel >= 512);

    // Default insertion depth
    uint8_t insertion_rrpv = 3; // LIP: always insert at LRU (3)
    if (use_bip) {
        // BIP: insert at MRU (0) with 1/32 probability, else at LRU (3)
        insertion_rrpv = ((rand() % 32) == 0) ? 0 : 3;
    }

    // ---- SHiP bias: high-reuse signature inserts at MRU (0)
    if (ship_table[ship_idx].reuse_counter >= 2)
        insertion_rrpv = 0;

    // ---- Streaming detector: streaming sets bypass fill if score==3
    if (streaming) {
        if (stream_score[set] == 3) {
            // Bypass fill: do not update replacement state (simulate no fill)
            return;
        } else {
            insertion_rrpv = 3;
        }
    }

    rrpv[set][way] = insertion_rrpv;
    line_sig[set][way] = sig;

    // ---- DIP set-dueling update ----
    // Only update PSEL for leader sets, on miss
    if (!hit) {
        if (leader == 1 && !streaming) { // LIP leader, not streaming
            if (psel < 1023) psel++;
        }
        else if (leader == 2 && !streaming) { // BIP leader, not streaming
            if (psel > 0) psel--;
        }
        // (Streaming sets don't update PSEL)
    }

    // ---- Periodic decay of SHiP counters ----
    if (access_counter % DECAY_PERIOD == 0) {
        for (uint32_t i = 0; i < SHIP_TABLE_SIZE; ++i)
            if (ship_table[i].reuse_counter > 0)
                ship_table[i].reuse_counter--;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    int high_reuse_pcs = 0;
    for (int i = 0; i < SHIP_TABLE_SIZE; ++i)
        if (ship_table[i].reuse_counter >= 2) high_reuse_pcs++;
    int streaming_sets = 0;
    for (int i = 0; i < LLC_SETS; ++i)
        if (stream_score[i] >= 2) streaming_sets++;
    std::cout << "SSB-LIP Policy: Signature-based Streaming Bypass with LIP" << std::endl;
    std::cout << "High-reuse PC signatures: " << high_reuse_pcs << "/" << SHIP_TABLE_SIZE << std::endl;
    std::cout << "Streaming sets (score>=2): " << streaming_sets << "/" << LLC_SETS << std::endl;
    std::cout << "Final PSEL: " << psel << " (0=LIP, 1023=BIP)" << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    int high_reuse_pcs = 0;
    for (int i = 0; i < SHIP_TABLE_SIZE; ++i)
        if (ship_table[i].reuse_counter >= 2) high_reuse_pcs++;
    int streaming_sets = 0;
    for (int i = 0; i < LLC_SETS; ++i)
        if (stream_score[i] >= 2) streaming_sets++;
    std::cout << "High-reuse PC signatures (heartbeat): " << high_reuse_pcs << "/" << SHIP_TABLE_SIZE << std::endl;
    std::cout << "Streaming sets (heartbeat): " << streaming_sets << "/" << LLC_SETS << std::endl;
    std::cout << "PSEL (heartbeat): " << psel << " (0=LIP, 1023=BIP)" << std::endl;
}