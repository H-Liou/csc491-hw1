#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- Per-block metadata ---
uint8_t rrpv[LLC_SETS][LLC_WAYS];      // 2 bits per block
uint8_t dead_bit[LLC_SETS][LLC_WAYS];  // 1 bit per block: 0=reused, 1=dead

// --- DRRIP set-dueling ---
#define NUM_LEADER_SETS 64
#define PSEL_BITS 10
uint16_t PSEL = 1 << (PSEL_BITS - 1); // 10-bit PSEL
uint8_t is_leader_set[LLC_SETS];      // 0=normal, 1=SRRIP leader, 2=BRRIP leader

// --- Streaming detector ---
uint64_t last_addr[LLC_SETS];          // last accessed address per set
uint8_t stream_state[LLC_SETS];        // 2 bits per set: 0=unknown, 1=streaming, 2=strong streaming

// Helper: assign leader sets
void AssignLeaderSets() {
    memset(is_leader_set, 0, sizeof(is_leader_set));
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i) {
        is_leader_set[i] = 1; // First 32: SRRIP leader
        is_leader_set[NUM_LEADER_SETS + i] = 2; // Next 32: BRRIP leader
    }
}

// Initialize replacement state
void InitReplacementState() {
    memset(rrpv, 2, sizeof(rrpv)); // distant
    memset(dead_bit, 1, sizeof(dead_bit)); // mark all as dead
    AssignLeaderSets();
    PSEL = 1 << (PSEL_BITS - 1);
    memset(last_addr, 0, sizeof(last_addr));
    memset(stream_state, 0, sizeof(stream_state));
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
        if (dead_bit[set][way])
            return way;
    // RRIP victim selection: evict block with rrpv==3
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
    // --- Streaming detector: update per-set state ---
    uint64_t addr_delta = (last_addr[set] == 0) ? 0 : std::abs((int64_t)paddr - (int64_t)last_addr[set]);
    last_addr[set] = paddr;
    // If delta is near block size or sequential, treat as streaming
    if (addr_delta == 64 || addr_delta == 128) {
        if (stream_state[set] < 2) stream_state[set]++;
    } else if (addr_delta > (64 * LLC_WAYS)) {
        if (stream_state[set] > 0) stream_state[set]--;
    }
    if (stream_state[set] > 2) stream_state[set] = 2;
    if (stream_state[set] < 0) stream_state[set] = 0;

    // --- DRRIP insertion policy ---
    bool use_brrip = false;
    if (is_leader_set[set] == 1) // SRRIP leader set
        use_brrip = false;
    else if (is_leader_set[set] == 2) // BRRIP leader set
        use_brrip = true;
    else
        use_brrip = (PSEL < (1 << (PSEL_BITS - 1)));

    // --- On hit: mark block reused, protect in cache ---
    if (hit) {
        dead_bit[set][way] = 0;      // Mark as reused
        rrpv[set][way] = 0;          // protect block
        // PSEL update for leader sets
        if (is_leader_set[set] == 1 && PSEL < ((1 << PSEL_BITS) - 1))
            PSEL++;
        else if (is_leader_set[set] == 2 && PSEL > 0)
            PSEL--;
    }

    // --- On fill (miss): dead-block and streaming logic ---
    if (!hit) {
        dead_bit[set][way] = 1; // Initially dead
        // Streaming detected: bypass or insert at distant RRPV
        if (stream_state[set] >= 2) {
            // If strong streaming, bypass with 1/2 probability
            if ((rand() & 1) == 0) {
                rrpv[set][way] = 3; // Simulate bypass (will be evicted soon)
                return;
            } else {
                rrpv[set][way] = 3; // Insert as distant
            }
        } else {
            // DRRIP insertion: SRRIP=2 (distant), BRRIP=3 (very distant, 1/32 probability insert at 2)
            if (!use_brrip)
                rrpv[set][way] = 2;
            else
                rrpv[set][way] = ((rand() & 31) == 0) ? 2 : 3;
        }
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    int dead_blocks = 0, reused_blocks = 0, streaming_sets = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (dead_bit[set][way]) dead_blocks++;
            else reused_blocks++;
        }
        if (stream_state[set] >= 2) streaming_sets++;
    }
    std::cout << "DRRIP-DeadBlock Hybrid + Adaptive Streaming Bypass Policy" << std::endl;
    std::cout << "Reused blocks: " << reused_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "Dead blocks: " << dead_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "Streaming sets: " << streaming_sets << "/" << LLC_SETS << std::endl;
    std::cout << "PSEL: " << PSEL << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    int dead_blocks = 0, reused_blocks = 0, streaming_sets = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (dead_bit[set][way]) dead_blocks++;
            else reused_blocks++;
        }
        if (stream_state[set] >= 2) streaming_sets++;
    }
    std::cout << "Reused blocks (heartbeat): " << reused_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "Dead blocks (heartbeat): " << dead_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "Streaming sets (heartbeat): " << streaming_sets << "/" << LLC_SETS << std::endl;
    std::cout << "PSEL (heartbeat): " << PSEL << std::endl;
}