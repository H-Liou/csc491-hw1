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
#define SHIP_SIG_BITS 4
#define SHIP_TABLE_SIZE (1 << SHIP_SIG_BITS) // 16 entries
struct SHIPEntry {
    uint8_t reuse_counter; // 2 bits
};
SHIPEntry ship_table[SHIP_TABLE_SIZE];

// ---- Per-line PC signatures ----
uint8_t line_sig[LLC_SETS][LLC_WAYS]; // 4 bits per line

// ---- DRRIP set-dueling ----
#define PSEL_BITS 10
uint16_t PSEL = (1 << (PSEL_BITS - 1)); // 10 bits, init to middle
#define NUM_LEADER_SETS 32
std::vector<uint16_t> SRRIP_leader_sets;
std::vector<uint16_t> BRRIP_leader_sets;

// ---- Streaming detector: per-set monotonicity ----
uint64_t last_addr[LLC_SETS]; // 48 bits per set (paddr)
uint8_t stream_score[LLC_SETS]; // 2 bits per set

// ---- Bypass bitmap ----
bool bypass_next[LLC_SETS]; // true if next fill should bypass

void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv));
    memset(ship_table, 1, sizeof(ship_table));
    memset(line_sig, 0, sizeof(line_sig));
    memset(last_addr, 0, sizeof(last_addr));
    memset(stream_score, 0, sizeof(stream_score));
    memset(bypass_next, 0, sizeof(bypass_next));

    // Assign leader sets (SRRIP: even, BRRIP: odd indices)
    SRRIP_leader_sets.clear();
    BRRIP_leader_sets.clear();
    for (uint16_t s = 0; s < LLC_SETS && SRRIP_leader_sets.size() < NUM_LEADER_SETS; ++s)
        if (s % (LLC_SETS / NUM_LEADER_SETS) == 0) SRRIP_leader_sets.push_back(s);
    for (uint16_t s = 0; s < LLC_SETS && BRRIP_leader_sets.size() < NUM_LEADER_SETS; ++s)
        if ((s + LLC_SETS/NUM_LEADER_SETS/2) % (LLC_SETS / NUM_LEADER_SETS) == 0) BRRIP_leader_sets.push_back(s);
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
    // Bypass logic: if bypass_next[set] is set, do not insert (return invalid way)
    if (bypass_next[set]) {
        bypass_next[set] = false; // reset after use
        return LLC_WAYS; // signal: do not insert
    }

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
    uint8_t sig = (uint8_t)((PC >> 2) & ((1 << SHIP_SIG_BITS) - 1)); // 4 bits
    line_sig[set][way < LLC_WAYS ? way : 0] = sig; // defensive for bypass

    // ---- SHiP outcome update ----
    if (hit && way < LLC_WAYS) {
        rrpv[set][way] = 0;
        if (ship_table[sig].reuse_counter < 3)
            ship_table[sig].reuse_counter++;
    } else if (way < LLC_WAYS) {
        // On miss/evict, penalize previous signature
        uint8_t evict_sig = line_sig[set][way];
        if (ship_table[evict_sig].reuse_counter > 0)
            ship_table[evict_sig].reuse_counter--;
    }

    // ---- DRRIP set-dueling outcome update ----
    bool is_SRRIP_leader = std::find(SRRIP_leader_sets.begin(), SRRIP_leader_sets.end(), set) != SRRIP_leader_sets.end();
    bool is_BRRIP_leader = std::find(BRRIP_leader_sets.begin(), BRRIP_leader_sets.end(), set) != BRRIP_leader_sets.end();
    if (is_SRRIP_leader && !hit && way < LLC_WAYS && current_set[way].valid)
        if (PSEL < ((1 << PSEL_BITS) - 1)) PSEL++;
    if (is_BRRIP_leader && !hit && way < LLC_WAYS && current_set[way].valid)
        if (PSEL > 0) PSEL--;

    // ---- Insertion depth selection ----
    uint8_t insertion_rrpv = 2; // default: SRRIP (insert at RRPV=2)
    if (PSEL >= (1 << (PSEL_BITS - 1))) {
        // SRRIP mode: insert at RRPV=2
        insertion_rrpv = 2;
    } else {
        // BRRIP mode: insert at RRPV=3 with 1/32 probability, else 2
        insertion_rrpv = (rand() % 32 == 0) ? 3 : 2;
    }

    // High-reuse PC signatures insert at MRU
    if (ship_table[sig].reuse_counter >= 2)
        insertion_rrpv = 0;

    // Streaming sets: bypass if not high-reuse PC
    if (streaming && ship_table[sig].reuse_counter < 2) {
        bypass_next[set] = true;
        // Do NOT insert: victim selection will skip fill
        return;
    } else {
        bypass_next[set] = false;
    }

    // Fill block if not bypassed
    if (way < LLC_WAYS) {
        rrpv[set][way] = insertion_rrpv;
        line_sig[set][way] = sig;
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
    std::cout << "HSD-SB Policy: Hybrid SHiP-DRRIP with Streaming Bypass" << std::endl;
    std::cout << "High-reuse PC signatures: " << high_reuse_pcs << "/" << SHIP_TABLE_SIZE << std::endl;
    std::cout << "Streaming sets (score>=2): " << streaming_sets << "/" << LLC_SETS << std::endl;
    std::cout << "PSEL value: " << PSEL << std::endl;
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
    std::cout << "PSEL value (heartbeat): " << PSEL << std::endl;
}