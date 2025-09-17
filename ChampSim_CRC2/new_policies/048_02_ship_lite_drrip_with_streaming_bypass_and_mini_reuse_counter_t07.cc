#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

//---------------------------------------------
// DRRIP set-dueling: 64 leader sets, 10-bit PSEL
#define NUM_LEADER_SETS 64
#define PSEL_MAX 1023
uint16_t PSEL = PSEL_MAX/2; // 10-bit

uint8_t leader_set_type[NUM_LEADER_SETS]; // 0: SRRIP, 1: BRRIP
uint8_t set_type[LLC_SETS];

//---------------------------------------------
// RRIP state: 2 bits per block
uint8_t rrpv[LLC_SETS][LLC_WAYS]; // 2 bits

//---------------------------------------------
// Mini-reuse counter: 1 bit per block, decayed periodically
uint8_t reuse_bit[LLC_SETS][LLC_WAYS]; // 0: not reused, 1: recently reused

//---------------------------------------------
// SHiP-lite: 4096-entry, 4-bit PC signature, 2-bit outcome counter
#define SHIP_TABLE_SIZE 4096
struct SHiPEntry {
    uint8_t counter; // 2 bits
    uint8_t valid;   // 1 bit
    uint8_t sig;     // 4 bits
};
SHiPEntry ship_table[SHIP_TABLE_SIZE];

// Per-block: store PC signature
uint8_t block_sig[LLC_SETS][LLC_WAYS]; // 4 bits per block

inline uint16_t SHIP_HASH(uint64_t PC) {
    // Simple hash: use lower 12 bits and fold to 4 bits signature
    return (PC ^ (PC >> 8) ^ (PC >> 16)) & (SHIP_TABLE_SIZE-1);
}
inline uint8_t SIG_HASH(uint64_t PC) {
    return (PC ^ (PC >> 8) ^ (PC >> 16)) & 0xF;
}

//---------------------------------------------
// Streaming detector: 2 bits per set
uint8_t stream_ctr[LLC_SETS]; // 0–3
uint64_t last_addr[LLC_SETS];

//---------------------------------------------
// Helper: assign leader sets
void InitLeaderSets() {
    // Pick first 32 for SRRIP, next 32 for BRRIP
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i) {
        leader_set_type[i] = (i < NUM_LEADER_SETS/2) ? 0 : 1;
    }
    // Map sets to leader/follower
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        if (set < NUM_LEADER_SETS)
            set_type[set] = leader_set_type[set];
        else
            set_type[set] = 2; // follower
    }
}

//---------------------------------------------
// Initialize replacement state
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv));    // distant
    memset(reuse_bit, 0, sizeof(reuse_bit));
    memset(block_sig, 0, sizeof(block_sig));
    memset(stream_ctr, 0, sizeof(stream_ctr));
    memset(last_addr, 0, sizeof(last_addr));
    memset(ship_table, 0, sizeof(ship_table));
    InitLeaderSets();
    PSEL = PSEL_MAX/2;
}

//---------------------------------------------
// Find victim in the set (prefer dead/reuse-bit==0, then RRIP)
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
    // Prefer blocks with reuse_bit==0 (approx dead)
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (reuse_bit[set][way] == 0)
            return way;
    // RRIP victim: RRPV==3
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] < 3)
                rrpv[set][way]++;
    }
}

//---------------------------------------------
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
    //--- Streaming detector update ---
    uint64_t addr_delta = (last_addr[set] > 0) ? (paddr - last_addr[set]) : 0;
    last_addr[set] = paddr;
    if (addr_delta == 64 || addr_delta == -64) {
        if (stream_ctr[set] < 3) stream_ctr[set]++;
    } else {
        if (stream_ctr[set] > 0) stream_ctr[set]--;
    }

    //--- SHiP-lite update ---
    uint16_t ship_idx = SHIP_HASH(PC);
    uint8_t sig = SIG_HASH(PC);
    // On fill, record signature
    if (!hit) {
        block_sig[set][way] = sig;
        ship_table[ship_idx].sig = sig;
        ship_table[ship_idx].valid = 1;
    }

    //--- Mini-reuse counter ---
    if (hit) {
        rrpv[set][way] = 0; // protect
        reuse_bit[set][way] = 1; // recently reused
        // Update SHiP table: increment on hit
        if (ship_table[ship_idx].valid && ship_table[ship_idx].sig == sig) {
            if (ship_table[ship_idx].counter < 3) ship_table[ship_idx].counter++;
        }
    } else {
        // Streaming detected: bypass
        if (stream_ctr[set] == 3) {
            rrpv[set][way] = 3;
            reuse_bit[set][way] = 0;
            return;
        }
        // DRRIP insertion: leader sets set policy
        uint8_t ins_rrpv = 3; // default distant
        if (set_type[set] == 0) { // SRRIP: insert at 2
            ins_rrpv = 2;
        } else if (set_type[set] == 1) { // BRRIP: insert at 3 most times, 1/32 at 2
            static uint32_t brrip_tick = 0;
            ins_rrpv = (brrip_tick++ % 32 == 0) ? 2 : 3;
        } else {
            // Follower: use PSEL
            ins_rrpv = (PSEL >= PSEL_MAX/2) ? 2 : ((rand() % 32 == 0) ? 2 : 3);
        }
        // SHiP-lite bias: if outcome counter high, insert at 0/1
        if (ship_table[ship_idx].valid && ship_table[ship_idx].sig == sig) {
            if (ship_table[ship_idx].counter >= 2)
                ins_rrpv = 1; // more aggressive protection for hot signature
        }
        rrpv[set][way] = ins_rrpv;
        reuse_bit[set][way] = 0; // assume not reused yet
    }

    //--- SHiP-lite: outcome decrement on eviction of block not reused
    if (!hit && reuse_bit[set][way] == 0) {
        if (ship_table[ship_idx].valid && ship_table[ship_idx].sig == sig) {
            if (ship_table[ship_idx].counter > 0) ship_table[ship_idx].counter--;
        }
    }

    //--- DRRIP set-dueling feedback ---
    if (!hit) return; // Only update PSEL on hit
    if (set < NUM_LEADER_SETS) {
        if (leader_set_type[set] == 0) { // SRRIP leader
            if (PSEL < PSEL_MAX) PSEL++;
        } else if (leader_set_type[set] == 1) { // BRRIP leader
            if (PSEL > 0) PSEL--;
        }
    }
}

//---------------------------------------------
// Periodic mini-reuse decay (call every N accesses)
void DecayReuseBits() {
    static uint64_t access_count = 0;
    access_count++;
    if ((access_count % 4096) == 0) { // decay every 4096 accesses
        for (uint32_t set = 0; set < LLC_SETS; ++set)
            for (uint32_t way = 0; way < LLC_WAYS; ++way)
                reuse_bit[set][way] = 0;
    }
}

//---------------------------------------------
// Print end-of-simulation statistics
void PrintStats() {
    int protected_blocks = 0, distant_blocks = 0, dead_blocks = 0, streaming_sets = 0, hot_sigs = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (rrpv[set][way] == 0) protected_blocks++;
            if (rrpv[set][way] == 3) distant_blocks++;
            if (reuse_bit[set][way] == 0) dead_blocks++;
        }
        if (stream_ctr[set] == 3) streaming_sets++;
    }
    for (uint32_t i = 0; i < SHIP_TABLE_SIZE; ++i)
        if (ship_table[i].counter >= 2) hot_sigs++;
    std::cout << "SHiP-Lite DRRIP + Streaming Bypass + Mini-Reuse Policy" << std::endl;
    std::cout << "Protected blocks: " << protected_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "Distant blocks: " << distant_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "Dead(reuse==0) blocks: " << dead_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "Streaming sets: " << streaming_sets << "/" << LLC_SETS << std::endl;
    std::cout << "Hot PC signatures: " << hot_sigs << "/" << SHIP_TABLE_SIZE << std::endl;
    std::cout << "PSEL: " << PSEL << "/" << PSEL_MAX << std::endl;
}

//---------------------------------------------
// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    int protected_blocks = 0, distant_blocks = 0, dead_blocks = 0, streaming_sets = 0, hot_sigs = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (rrpv[set][way] == 0) protected_blocks++;
            if (rrpv[set][way] == 3) distant_blocks++;
            if (reuse_bit[set][way] == 0) dead_blocks++;
        }
        if (stream_ctr[set] == 3) streaming_sets++;
    }
    for (uint32_t i = 0; i < SHIP_TABLE_SIZE; ++i)
        if (ship_table[i].counter >= 2) hot_sigs++;
    std::cout << "Protected blocks (heartbeat): " << protected_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "Distant blocks (heartbeat): " << distant_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "Dead(reuse==0) blocks (heartbeat): " << dead_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "Streaming sets (heartbeat): " << streaming_sets << "/" << LLC_SETS << std::endl;
    std::cout << "Hot PC signatures (heartbeat): " << hot_sigs << "/" << SHIP_TABLE_SIZE << std::endl;
    std::cout << "PSEL (heartbeat): " << PSEL << "/" << PSEL_MAX << std::endl;
}