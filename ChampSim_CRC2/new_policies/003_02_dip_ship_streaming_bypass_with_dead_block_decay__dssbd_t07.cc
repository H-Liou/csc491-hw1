#include <vector>
#include <cstdint>
#include <cstring>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// DIP parameters
#define DIP_LEADER_SETS 32
#define PSEL_BITS 10
#define PSEL_MAX ((1 << PSEL_BITS) - 1)
#define PSEL_INIT (PSEL_MAX / 2)

// SHiP-lite parameters
#define SHIP_SIG_BITS 6
#define SHIP_SIG_ENTRIES (1 << SHIP_SIG_BITS)
#define SHIP_COUNTER_BITS 2
#define SHIP_COUNTER_MAX ((1 << SHIP_COUNTER_BITS) - 1)
#define SHIP_REUSE_HIGH (SHIP_COUNTER_MAX - 1)

// Dead-block counter
#define DEAD_BITS 2
#define DEAD_MAX ((1 << DEAD_BITS) - 1)
#define DEAD_DECAY_PERIOD 4096

// Streaming detector
#define STREAM_DELTA_HISTORY 4
#define STREAM_DELTA_THRESHOLD 3 // 3/4 monotonic deltas triggers streaming

struct BLOCK_META {
    uint8_t dead;         // 2 bits
    uint8_t ship_sig;     // 6 bits
};

struct SHIP_SIG_ENTRY {
    uint8_t reuse_counter; // 2 bits
};

struct STREAM_DETECTOR {
    uint64_t last_addr;
    int64_t delta_history[STREAM_DELTA_HISTORY];
    uint8_t ptr;
    bool streaming;
};

std::vector<BLOCK_META> block_meta;
std::vector<SHIP_SIG_ENTRY> ship_sig_table;
std::vector<STREAM_DETECTOR> stream_detector;

// DIP set-dueling: leader sets and PSEL
std::vector<uint8_t> is_leader_LIP; // 1 if LIP leader, 0 otherwise
std::vector<uint8_t> is_leader_BIP; // 1 if BIP leader, 0 otherwise
uint16_t psel = PSEL_INIT;

uint64_t access_counter = 0;
uint64_t streaming_bypass = 0;
uint64_t dead_decay_count = 0;

// Helper: get SHiP signature from PC
inline uint8_t get_ship_sig(uint64_t PC) {
    return (PC ^ (PC >> 2) ^ (PC >> 7)) & (SHIP_SIG_ENTRIES - 1);
}

// Helper: get block meta index
inline size_t get_block_meta_idx(uint32_t set, uint32_t way) {
    return set * LLC_WAYS + way;
}

// Streaming detection: updates per access
void update_streaming_detector(uint32_t set, uint64_t curr_addr) {
    STREAM_DETECTOR &sd = stream_detector[set];
    int64_t delta = curr_addr - sd.last_addr;
    if (sd.last_addr != 0) {
        sd.delta_history[sd.ptr] = delta;
        sd.ptr = (sd.ptr + 1) % STREAM_DELTA_HISTORY;
    }
    sd.last_addr = curr_addr;
    // Check monotonicity
    int positive = 0, negative = 0, nonzero = 0;
    for (int i = 0; i < STREAM_DELTA_HISTORY; i++) {
        if (sd.delta_history[i] > 0) positive++;
        else if (sd.delta_history[i] < 0) negative++;
        if (sd.delta_history[i] != 0) nonzero++;
    }
    if (nonzero >= STREAM_DELTA_THRESHOLD &&
        (positive >= STREAM_DELTA_THRESHOLD || negative >= STREAM_DELTA_THRESHOLD)) {
        sd.streaming = true;
    } else {
        sd.streaming = false;
    }
}

// Dead-block decay: periodically decay all dead counters
void decay_dead_counters() {
    for (size_t i = 0; i < block_meta.size(); i++) {
        if (block_meta[i].dead > 0)
            block_meta[i].dead--;
    }
}

// DIP leader set selection
void assign_leader_sets() {
    is_leader_LIP.resize(LLC_SETS, 0);
    is_leader_BIP.resize(LLC_SETS, 0);
    // Interleave first DIP_LEADER_SETS sets for LIP, next for BIP
    for (uint32_t i = 0; i < DIP_LEADER_SETS; i++) {
        is_leader_LIP[i] = 1;
        is_leader_BIP[DIP_LEADER_SETS + i] = 1;
    }
}

// Initialization
void InitReplacementState() {
    block_meta.resize(LLC_SETS * LLC_WAYS);
    ship_sig_table.resize(SHIP_SIG_ENTRIES);
    stream_detector.resize(LLC_SETS);

    for (size_t i = 0; i < block_meta.size(); i++) {
        block_meta[i].dead = DEAD_MAX / 2;
        block_meta[i].ship_sig = 0;
    }
    for (size_t i = 0; i < ship_sig_table.size(); i++) {
        ship_sig_table[i].reuse_counter = 0;
    }
    for (size_t i = 0; i < stream_detector.size(); i++) {
        stream_detector[i].last_addr = 0;
        memset(stream_detector[i].delta_history, 0, sizeof(stream_detector[i].delta_history));
        stream_detector[i].ptr = 0;
        stream_detector[i].streaming = false;
    }
    assign_leader_sets();
    access_counter = 0;
    streaming_bypass = 0;
    dead_decay_count = 0;
    psel = PSEL_INIT;
}

// Victim selection: evict block with lowest dead counter, tie-break by way 0
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    uint32_t victim = 0;
    uint8_t min_dead = DEAD_MAX + 1;
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        size_t idx = get_block_meta_idx(set, way);
        if (block_meta[idx].dead < min_dead) {
            min_dead = block_meta[idx].dead;
            victim = way;
        }
    }
    return victim;
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
    size_t idx = get_block_meta_idx(set, way);
    BLOCK_META &meta = block_meta[idx];

    // Streaming detection (per set)
    update_streaming_detector(set, paddr);

    // Periodically decay dead counters (every DEAD_DECAY_PERIOD accesses)
    if ((access_counter & (DEAD_DECAY_PERIOD - 1)) == 0) {
        decay_dead_counters();
        dead_decay_count++;
    }

    uint8_t sig = get_ship_sig(PC);

    // On streaming phase: bypass cache fill
    if (stream_detector[set].streaming) {
        // Do not insert block (simulate bypass): leave meta as-is
        streaming_bypass++;
        return;
    }

    // On cache hit
    if (hit) {
        // Update SHiP reuse counter
        if (ship_sig_table[sig].reuse_counter < SHIP_COUNTER_MAX)
            ship_sig_table[sig].reuse_counter++;
        // Mark block as reused
        if (meta.dead > 0) meta.dead--;
        return;
    }

    // On cache fill (miss)
    meta.ship_sig = sig;

    // SHiP predicts high reuse: insert at MRU, else follow DIP
    if (ship_sig_table[sig].reuse_counter >= SHIP_REUSE_HIGH) {
        meta.dead = 0; // likely reused soon
    } else {
        // DIP: select policy for non-high-reuse blocks
        if (is_leader_LIP[set]) {
            // LIP: insert at LRU (max dead)
            meta.dead = DEAD_MAX;
        } else if (is_leader_BIP[set]) {
            // BIP: insert at MRU with probability 1/32, else LRU
            if ((access_counter & 31) == 0)
                meta.dead = 0;
            else
                meta.dead = DEAD_MAX;
        } else {
            // Follower sets: use PSEL to choose
            if (psel >= (PSEL_MAX / 2))
                meta.dead = DEAD_MAX; // LIP
            else
                meta.dead = ((access_counter & 31) == 0) ? 0 : DEAD_MAX; // BIP
        }
    }

    // On victim eviction: update SHiP reuse counter according to block's dead
    uint32_t victim_way = GetVictimInSet(cpu, set, nullptr, PC, paddr, type);
    size_t victim_idx = get_block_meta_idx(set, victim_way);
    uint8_t victim_sig = block_meta[victim_idx].ship_sig;
    // If block was reused before eviction, increment reuse; else, decrement
    if (block_meta[victim_idx].dead == 0) {
        if (ship_sig_table[victim_sig].reuse_counter < SHIP_COUNTER_MAX)
            ship_sig_table[victim_sig].reuse_counter++;
    } else {
        if (ship_sig_table[victim_sig].reuse_counter > 0)
            ship_sig_table[victim_sig].reuse_counter--;
    }

    // DIP: update PSEL for leader sets only
    if (is_leader_LIP[set] && hit) {
        if (psel < PSEL_MAX) psel++;
    }
    if (is_leader_BIP[set] && hit) {
        if (psel > 0) psel--;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "DSSBD: DIP-SHiP Streaming Bypass Dead-Block stats\n";
    std::cout << "Total accesses: " << access_counter << "\n";
    std::cout << "Streaming fills bypassed: " << streaming_bypass << "\n";
    std::cout << "Dead-block decay rounds: " << dead_decay_count << "\n";
    size_t streaming_sets = 0;
    for (size_t i = 0; i < stream_detector.size(); i++) {
        if (stream_detector[i].streaming) streaming_sets++;
    }
    std::cout << "Streaming sets detected: " << streaming_sets << "\n";
    std::cout << "PSEL final value: " << psel << "\n";
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    std::cout << "DSSBD heartbeat: accesses=" << access_counter
              << ", streaming_bypass=" << streaming_bypass
              << ", dead_decay=" << dead_decay_count
              << ", PSEL=" << psel << "\n";
}