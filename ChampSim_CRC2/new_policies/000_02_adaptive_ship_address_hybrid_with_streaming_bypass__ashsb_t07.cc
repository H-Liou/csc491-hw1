#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

// Parameters
#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// SHiP-lite: 6-bit PC signature, 2-bit outcome counter
#define SHIP_SIG_BITS 6
#define SHIP_SIG_ENTRIES 256
#define SHIP_SIG_MASK ((1 << SHIP_SIG_BITS) - 1)
#define SHIP_COUNTER_BITS 2

// Address-based reuse: 2 bits per block
#define REUSE_BITS 2

// Streaming detector: 2 bits per set for confidence, store last address per set
#define STREAM_CONF_BITS 2

// DRRIP set-dueling
#define PSEL_BITS 10
#define LEADER_SETS 64

// Replacement state
struct BLOCK_META {
    uint8_t rrpv;                   // 2 bits
    uint8_t addr_reuse;             // 2 bits
    uint8_t ship_sig;               // 6 bits
};

struct SHIP_SIG_ENTRY {
    uint8_t counter;                // 2 bits
};

struct SET_STREAM {
    uint64_t last_addr;
    int64_t last_delta;             // signed delta
    uint8_t conf;                   // 2 bits
};

// Per-block metadata
BLOCK_META repl_meta[LLC_SETS][LLC_WAYS];

// SHiP-lite table
SHIP_SIG_ENTRY ship_table[SHIP_SIG_ENTRIES];

// Streaming detector per set
SET_STREAM stream_table[LLC_SETS];

// DRRIP set-dueling: 10-bit PSEL, 64 leader sets each for SRRIP/BRRIP
uint16_t PSEL = (1 << (PSEL_BITS-1)); // mid value
uint8_t set_type[LLC_SETS]; // 0: follower, 1: SRRIP leader, 2: BRRIP leader

// Helper: PC signature
inline uint8_t get_ship_sig(uint64_t PC) {
    return (PC ^ (PC >> 4)) & SHIP_SIG_MASK;
}

// Helper: set type assignment (64 SRRIP, 64 BRRIP, rest follower)
void assign_set_types() {
    memset(set_type, 0, sizeof(set_type));
    for (uint32_t i = 0; i < LLC_SETS; i++) {
        if (i < LEADER_SETS)
            set_type[i] = 1; // SRRIP leader
        else if (i < 2*LEADER_SETS)
            set_type[i] = 2; // BRRIP leader
        else
            set_type[i] = 0; // follower
    }
}

void InitReplacementState() {
    // Zero all metadata
    memset(repl_meta, 0, sizeof(repl_meta));
    memset(ship_table, 0, sizeof(ship_table));
    memset(stream_table, 0, sizeof(stream_table));
    assign_set_types();
}

// Streaming detector: detect monotonic stride streams
inline bool detect_stream(uint32_t set, uint64_t paddr) {
    SET_STREAM &st = stream_table[set];
    int64_t delta = int64_t(paddr) - int64_t(st.last_addr);

    if (st.last_addr != 0 && (delta == st.last_delta) && (delta != 0)) {
        if (st.conf < 3) st.conf++;
    } else {
        if (st.conf > 0) st.conf--;
    }
    st.last_addr = paddr;
    st.last_delta = delta;
    // Consider streaming if confidence >=2
    return (st.conf >= 2);
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
    // Streaming bypass: if strong streaming detected, bypass (no fill)
    if (detect_stream(set, paddr)) {
        // Special value: bypass (simulate as highest RRPV block eviction)
        for (uint32_t way = 0; way < LLC_WAYS; way++)
            if (repl_meta[set][way].rrpv == 3)
                return way;
        // If no block with RRPV=3, age all and retry
        for (uint32_t way = 0; way < LLC_WAYS; way++)
            repl_meta[set][way].rrpv = 3;
        // Evict any
        return 0;
    }

    // Normal victim selection: RRIP
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; way++) {
            if (repl_meta[set][way].rrpv == 3)
                return way;
        }
        // Age all blocks
        for (uint32_t way = 0; way < LLC_WAYS; way++)
            if (repl_meta[set][way].rrpv < 3)
                repl_meta[set][way].rrpv++;
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
    // Streaming detector update
    bool is_stream = detect_stream(set, paddr);

    // SHiP signature
    uint8_t sig = get_ship_sig(PC);

    // On hit: update SHiP counter and address reuse counter
    if (hit) {
        if (ship_table[sig].counter < 3) ship_table[sig].counter++;
        if (repl_meta[set][way].addr_reuse < 3) repl_meta[set][way].addr_reuse++;
        // On hit, reset RRPV to 0 (protect)
        repl_meta[set][way].rrpv = 0;
        return;
    }

    // On miss (fill): choose insertion depth

    // Set-dueling: pick insertion depth
    uint8_t insert_rrpv = 2; // favorable
    uint8_t settype = set_type[set];
    if (settype == 1) // SRRIP leader
        insert_rrpv = 2;
    else if (settype == 2) // BRRIP leader
        insert_rrpv = (rand() % 32 == 0) ? 2 : 3;
    else // follower
        insert_rrpv = (PSEL >= (1 << (PSEL_BITS-1))) ? 2 : ((rand() % 32 == 0) ? 2 : 3);

    // Streaming: if detected, force distant/bypass
    if (is_stream)
        insert_rrpv = 3;

    // Dead-block approximation: if per-block addr_reuse low, prefer distant
    if (repl_meta[set][way].addr_reuse == 0)
        insert_rrpv = 3;

    // SHiP: if signature reuse poor, prefer distant
    if (ship_table[sig].counter == 0)
        insert_rrpv = 3;

    // Insert block
    repl_meta[set][way].rrpv = insert_rrpv;
    repl_meta[set][way].ship_sig = sig;
    repl_meta[set][way].addr_reuse = 0; // reset reuse

    // Update SHiP outcome counter on victim (eviction): if not reused, decay
    uint8_t victim_sig = repl_meta[set][way].ship_sig;
    if (repl_meta[set][way].rrpv == 3 && ship_table[victim_sig].counter > 0)
        ship_table[victim_sig].counter--;

    // Dead-block: decay addr_reuse counter on eviction
    if (repl_meta[set][way].addr_reuse > 0)
        repl_meta[set][way].addr_reuse--;

    // PSEL update: on leader sets, update based on hit/miss
    if (set_type[set] == 1) { // SRRIP leader
        if (hit && PSEL < ((1 << PSEL_BITS) - 1)) PSEL++;
        else if (!hit && PSEL > 0) PSEL--;
    } else if (set_type[set] == 2) { // BRRIP leader
        if (hit && PSEL > 0) PSEL--;
        else if (!hit && PSEL < ((1 << PSEL_BITS) - 1)) PSEL++;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "Adaptive SHiP-Address Hybrid Streaming Bypass stats\n";
    std::cout << "Final PSEL: " << PSEL << std::endl;
    // Optionally, print SHiP counters or streaming stats
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Optional: print stats
}