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
#define SHIP_TABLE_SIZE 1024 // 1024 entries, 6-bit index (PC % 1024)
struct SHIPEntry {
    uint8_t reuse_counter; // 2 bits
};
SHIPEntry ship_table[SHIP_TABLE_SIZE];

// ---- Per-line PC signatures ----
uint16_t line_sig[LLC_SETS][LLC_WAYS]; // 6 bits per line

// ---- Dead-block filter: 1 bit per line ----
uint8_t dead_block[LLC_SETS][LLC_WAYS]; // 1 bit per line

// ---- Streaming detector: per-set monotonicity ----
uint64_t last_addr[LLC_SETS]; // 48 bits per set (paddr)
uint8_t stream_score[LLC_SETS]; // 2 bits per set

// ---- DIP-style set-dueling for LIP/BIP ----
#define NUM_LEADER_SETS 32
uint8_t is_lip_leader[LLC_SETS];
uint8_t is_bip_leader[LLC_SETS];
uint16_t psel; // 10 bits

// ---- Periodic decay for dead-block filter ----
uint64_t access_counter = 0;
#define DECAY_PERIOD 100000

void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv));
    memset(ship_table, 1, sizeof(ship_table));
    memset(line_sig, 0, sizeof(line_sig));
    memset(dead_block, 0, sizeof(dead_block));
    memset(is_lip_leader, 0, sizeof(is_lip_leader));
    memset(is_bip_leader, 0, sizeof(is_bip_leader));
    memset(last_addr, 0, sizeof(last_addr));
    memset(stream_score, 0, sizeof(stream_score));
    psel = (1 << 9); // 512

    // Assign leader sets: first NUM_LEADER_SETS for LIP, next NUM_LEADER_SETS for BIP
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i) {
        is_lip_leader[i] = 1;
        is_bip_leader[LLC_SETS/2 + i] = 1;
    }
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

    // Prefer dead blocks
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (dead_block[set][way])
            return way;

    // RRIP: select block with max RRPV (3), else increment all RRPV
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
    uint16_t ship_idx = sig; // Use as index
    line_sig[set][way] = sig;

    // ---- SHiP outcome update ----
    if (hit) {
        // On hit, promote block and increment reuse counter
        rrpv[set][way] = 0;
        if (ship_table[ship_idx].reuse_counter < 3)
            ship_table[ship_idx].reuse_counter++;
        dead_block[set][way] = 0; // Not dead
    } else {
        // On miss/evict, penalize previous signature if block was dead
        uint16_t evict_sig = line_sig[set][way];
        if (ship_table[evict_sig].reuse_counter > 0)
            ship_table[evict_sig].reuse_counter--;
        dead_block[set][way] = 1; // Mark as dead
    }

    // ---- DIP-style set-dueling: choose insertion policy ----
    bool use_bip = false;
    if (is_lip_leader[set]) {
        use_bip = false;
    } else if (is_bip_leader[set]) {
        use_bip = true;
    } else {
        use_bip = (psel >= (1 << 9));
    }

    // ---- Insertion depth selection ----
    uint8_t insertion_rrpv = 3; // default: insert at LRU (LIP)
    if (use_bip) {
        insertion_rrpv = (rand() % 100 < 5) ? 2 : 3; // BIP: 5% insert at MRU-1, 95% at LRU
    }

    // ---- SHiP bias: high-reuse PCs insert at MRU ----
    if (ship_table[ship_idx].reuse_counter >= 2)
        insertion_rrpv = 0;

    // ---- Streaming logic: streaming sets bypass low-reuse PCs ----
    if (streaming && ship_table[ship_idx].reuse_counter == 0) {
        // Bypass: do not promote block, mark as dead
        rrpv[set][way] = 3;
        dead_block[set][way] = 1;
        line_sig[set][way] = sig;
        return;
    }

    rrpv[set][way] = insertion_rrpv;
    dead_block[set][way] = 0;
    line_sig[set][way] = sig;

    // ---- Set-dueling PSEL update ----
    if (is_lip_leader[set]) {
        if (hit && psel < 1023) psel++;
    } else if (is_bip_leader[set]) {
        if (hit && psel > 0) psel--;
    }

    // ---- Periodic decay of dead-block filter ----
    if (access_counter % DECAY_PERIOD == 0) {
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            for (uint32_t w = 0; w < LLC_WAYS; ++w)
                dead_block[s][w] = 0;
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
    int dead_blocks = 0;
    for (int i = 0; i < LLC_SETS; ++i)
        for (int j = 0; j < LLC_WAYS; ++j)
            if (dead_block[i][j]) dead_blocks++;
    std::cout << "HSL-DBF Policy: Hybrid SHiP-LIP + Streaming Dead-Block Filter" << std::endl;
    std::cout << "High-reuse PC signatures: " << high_reuse_pcs << "/" << SHIP_TABLE_SIZE << std::endl;
    std::cout << "Streaming sets (score>=2): " << streaming_sets << "/" << LLC_SETS << std::endl;
    std::cout << "Dead blocks: " << dead_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "Final PSEL value: " << psel << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    int high_reuse_pcs = 0;
    for (int i = 0; i < SHIP_TABLE_SIZE; ++i)
        if (ship_table[i].reuse_counter >= 2) high_reuse_pcs++;
    int streaming_sets = 0;
    for (int i = 0; i < LLC_SETS; ++i)
        if (stream_score[i] >= 2) streaming_sets++;
    int dead_blocks = 0;
    for (int i = 0; i < LLC_SETS; ++i)
        for (int j = 0; j < LLC_WAYS; ++j)
            if (dead_block[i][j]) dead_blocks++;
    std::cout << "High-reuse PC signatures (heartbeat): " << high_reuse_pcs << "/" << SHIP_TABLE_SIZE << std::endl;
    std::cout << "Streaming sets (heartbeat): " << streaming_sets << "/" << LLC_SETS << std::endl;
    std::cout << "Dead blocks (heartbeat): " << dead_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
}