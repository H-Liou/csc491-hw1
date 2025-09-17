#include <vector>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- DIP metadata ---
#define NUM_LEADER_SETS 32
#define PSEL_BITS 10
uint16_t PSEL = (1 << (PSEL_BITS - 1)); // 10-bit selector, initialized mid
bool is_lip_leader[LLC_SETS];
bool is_bip_leader[LLC_SETS];

// --- SHiP-lite: 6-bit PC signature per block, 2-bit outcome per signature ---
#define SIG_BITS 6
#define SIG_TABLE_SIZE 2048
uint8_t block_sig[LLC_SETS][LLC_WAYS]; // [0,63]
uint8_t sig_ctr[SIG_TABLE_SIZE];       // 2-bit saturating counter per signature

// --- Dead-block flag: 1-bit per block ---
uint8_t dead_flag[LLC_SETS][LLC_WAYS]; // 0=live, 1=dead

// --- Streaming detector: 1-bit per set, monotonic delta ---
uint8_t streaming_set[LLC_SETS]; // 0=not streaming, 1=streaming
uint64_t last_addr[LLC_SETS];

// --- For periodic decay (SHIP outcome counters) ---
uint64_t access_counter = 0;
#define DECAY_PERIOD (SIG_TABLE_SIZE * 8)

// --- Helper: assign leader sets for DIP ---
void assign_leader_sets() {
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        is_lip_leader[set] = false;
        is_bip_leader[set] = false;
    }
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i) {
        is_lip_leader[i] = true;
        is_bip_leader[LLC_SETS - 1 - i] = true;
    }
}

void InitReplacementState() {
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            block_sig[set][way] = 0;
            dead_flag[set][way] = 0;
        }
        streaming_set[set] = 0;
        last_addr[set] = 0;
    }
    for (uint32_t i = 0; i < SIG_TABLE_SIZE; ++i)
        sig_ctr[i] = 1; // neutral
    PSEL = (1 << (PSEL_BITS - 1));
    assign_leader_sets();
    access_counter = 0;
}

// DIP victim selection: prefer dead blocks, else LRU
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // First, try to evict a dead block
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (dead_flag[set][way])
            return way;
    // Else, evict true LRU (lowest address, as a proxy)
    uint32_t victim = 0;
    uint64_t min_addr = current_set[0].address;
    for (uint32_t way = 1; way < LLC_WAYS; ++way) {
        if (current_set[way].address < min_addr) {
            min_addr = current_set[way].address;
            victim = way;
        }
    }
    return victim;
}

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

    // --- Streaming detector update (1-bit monotonic) ---
    int64_t delta = int64_t(paddr) - int64_t(last_addr[set]);
    if (delta == 64 || delta == -64)
        streaming_set[set] = 1;
    else if (delta != 0)
        streaming_set[set] = 0;
    last_addr[set] = paddr;

    // --- SHiP signature extraction ---
    uint32_t sig = (PC ^ (paddr>>6)) & ((1<<SIG_BITS)-1);

    // --- Update SHiP outcome counters ---
    if (hit) {
        dead_flag[set][way] = 0; // block is live
        if (sig_ctr[sig] < 3)
            sig_ctr[sig]++;
    } else {
        // On eviction, decrement signature counter (min 0)
        uint32_t victim_sig = block_sig[set][way];
        if (sig_ctr[victim_sig] > 0)
            sig_ctr[victim_sig]--;
        dead_flag[set][way] = 1; // mark as dead on miss/eviction
    }

    // --- Periodic decay of signature counters ---
    if (access_counter % DECAY_PERIOD == 0) {
        for (uint32_t i = 0; i < SIG_TABLE_SIZE; ++i)
            if (sig_ctr[i] > 0)
                sig_ctr[i]--;
    }

    // --- DIP insertion depth selection ---
    bool use_lip = false, use_bip = false;
    if (is_lip_leader[set])
        use_lip = true;
    else if (is_bip_leader[set])
        use_bip = true;
    else
        use_lip = (PSEL >= (1 << (PSEL_BITS - 1)));

    // --- Streaming bypass logic: if streaming detected, bypass with probability 3/4 ---
    bool is_streaming = streaming_set[set];
    bool bypass = false;
    if (is_streaming) {
        // Use PC/paddr entropy for coin-flip: bypass if lower 2 bits != 0
        if (((PC ^ paddr) & 0x3) != 0)
            bypass = true;
    }

    // --- SHiP bias: If signature has high reuse, override DIP and insert at MRU ---
    bool strong_sig = (sig_ctr[sig] >= 2);

    // --- DIP PSEL update on leader sets ---
    if (!hit) {
        if (is_lip_leader[set]) {
            if (!bypass && hit)
                PSEL = (PSEL < ((1<<PSEL_BITS)-1)) ? (PSEL+1) : PSEL;
        }
        if (is_bip_leader[set]) {
            if (!bypass && hit)
                PSEL = (PSEL > 0) ? (PSEL-1) : 0;
        }
    }

    // --- Insertion logic ---
    if (bypass && !hit) {
        // Streaming detected: bypass block (mark as dead, don't update sig)
        dead_flag[set][way] = 1;
        block_sig[set][way] = sig;
        return;
    }
    else if (strong_sig) {
        // SHiP bias: reusable block, insert at MRU (clear dead flag)
        dead_flag[set][way] = 0;
    }
    else if (use_lip) {
        // LIP: always insert at LRU (mark as dead)
        dead_flag[set][way] = 1;
    }
    else if (use_bip) {
        // BIP: insert at MRU with prob 1/32, else at LRU
        if (((PC ^ paddr) & 0x1F) == 0)
            dead_flag[set][way] = 0;
        else
            dead_flag[set][way] = 1;
    }
    else {
        // Default: conservative, insert as dead
        dead_flag[set][way] = 1;
    }

    // --- Update block's signature ---
    block_sig[set][way] = sig;
}

void PrintStats() {
    int sig2 = 0, sig3 = 0;
    for (uint32_t i = 0; i < SIG_TABLE_SIZE; ++i) {
        if (sig_ctr[i] == 2) sig2++;
        if (sig_ctr[i] == 3) sig3++;
    }
    std::cout << "SDSD: sig_ctr==2: " << sig2 << " / " << SIG_TABLE_SIZE << std::endl;
    std::cout << "SDSD: sig_ctr==3: " << sig3 << std::endl;
    int streaming_sets = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        if (streaming_set[set])
            streaming_sets++;
    std::cout << "SDSD: Streaming sets detected: " << streaming_sets << " / " << LLC_SETS << std::endl;
}

void PrintStats_Heartbeat() {
    int sig3 = 0;
    for (uint32_t i = 0; i < SIG_TABLE_SIZE; ++i)
        if (sig_ctr[i] == 3) sig3++;
    std::cout << "SDSD: sig_ctr==3: " << sig3 << std::endl;
    int streaming_sets = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        if (streaming_set[set])
            streaming_sets++;
    std::cout << "SDSD: Streaming sets: " << streaming_sets << std::endl;
}