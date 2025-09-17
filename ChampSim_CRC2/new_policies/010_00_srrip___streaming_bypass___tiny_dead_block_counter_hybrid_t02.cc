#include <vector>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// SRRIP: 2-bit RRPV per block
struct BLOCK_META {
    uint8_t rrpv;      // 2 bits
    uint8_t dead_cnt;  // 2 bits
    uint64_t last_addr; // For streaming detection (lower bits only)
};

std::vector<BLOCK_META> block_meta;

// Streaming detector: per-set last address, delta, and streaming score
struct STREAM_DETECT {
    uint64_t last_addr;
    int64_t last_delta;
    uint8_t stream_score; // 2 bits
};
std::vector<STREAM_DETECT> stream_detect;

// SRRIP set-dueling: 32 leader sets, 10-bit PSEL
#define NUM_LEADER_SETS 32
#define PSEL_BITS 10
uint16_t psel = (1 << (PSEL_BITS - 1));
std::vector<uint8_t> leader_set_type; // 0:SRRIP-MRU, 1:SRRIP-LRU

// Stats
uint64_t access_counter = 0;
uint64_t hits = 0;
uint64_t stream_bypass = 0;
uint64_t dead_evictions = 0;
uint64_t srrip_mru_inserts = 0;
uint64_t srrip_lru_inserts = 0;

// Helper: get block meta index
inline size_t get_block_meta_idx(uint32_t set, uint32_t way) {
    return set * LLC_WAYS + way;
}

// Initialization
void InitReplacementState() {
    block_meta.resize(LLC_SETS * LLC_WAYS);
    stream_detect.resize(LLC_SETS);
    leader_set_type.resize(NUM_LEADER_SETS);

    // Assign leader sets: evenly spaced
    for (size_t i = 0; i < NUM_LEADER_SETS; i++) {
        leader_set_type[i] = (i < NUM_LEADER_SETS / 2) ? 0 : 1; // 0:MRU, 1:LRU
    }

    for (size_t i = 0; i < block_meta.size(); i++) {
        block_meta[i].rrpv = 3; // LRU
        block_meta[i].dead_cnt = 0;
        block_meta[i].last_addr = 0;
    }
    for (size_t i = 0; i < stream_detect.size(); i++) {
        stream_detect[i].last_addr = 0;
        stream_detect[i].last_delta = 0;
        stream_detect[i].stream_score = 0;
    }

    access_counter = 0;
    hits = 0;
    stream_bypass = 0;
    dead_evictions = 0;
    srrip_mru_inserts = 0;
    srrip_lru_inserts = 0;
}

// Victim selection: prefer blocks with dead_cnt==3, else RRIP
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // First, try to find a block with dead_cnt==3 (dead block)
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        size_t idx = get_block_meta_idx(set, way);
        if (block_meta[idx].dead_cnt == 3)
            return way;
    }
    // Next, standard RRIP: find block with RRPV==3
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        size_t idx = get_block_meta_idx(set, way);
        if (block_meta[idx].rrpv == 3)
            return way;
    }
    // If none, increment RRPVs and retry
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        size_t idx = get_block_meta_idx(set, way);
        if (block_meta[idx].rrpv < 3)
            block_meta[idx].rrpv++;
    }
    // Second pass
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        size_t idx = get_block_meta_idx(set, way);
        if (block_meta[idx].rrpv == 3)
            return way;
    }
    // If still none, pick way 0
    return 0;
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

    // --- Dead-block decay: every 4096 accesses, decay all dead_cnt by 1 (if >0)
    if ((access_counter & 0xFFF) == 0) {
        for (size_t i = 0; i < block_meta.size(); i++) {
            if (block_meta[i].dead_cnt > 0)
                block_meta[i].dead_cnt--;
        }
    }

    // --- Streaming detector ---
    STREAM_DETECT &sd = stream_detect[set];
    int64_t delta = int64_t(paddr) - int64_t(sd.last_addr);
    bool is_stream = false;
    if (sd.last_addr != 0 && delta != 0 && (delta == sd.last_delta)) {
        // Near-monotonic stride detected
        if (sd.stream_score < 3) sd.stream_score++;
    } else {
        if (sd.stream_score > 0) sd.stream_score--;
    }
    if (sd.stream_score >= 2) is_stream = true;
    sd.last_delta = delta;
    sd.last_addr = paddr;

    // --- On hit: promote block to MRU, reset dead_cnt
    if (hit) {
        meta.rrpv = 0;
        meta.dead_cnt = 0;
        hits++;
        return;
    }

    // --- On miss: insertion ---
    // SRRIP set-dueling: leader sets use fixed policy, others use PSEL
    bool is_leader = (set % (LLC_SETS / NUM_LEADER_SETS)) == 0;
    uint8_t leader_type = 0;
    if (is_leader) {
        leader_type = leader_set_type[set / (LLC_SETS / NUM_LEADER_SETS)];
    }
    bool use_mru = false;
    if (is_leader) {
        use_mru = (leader_type == 0);
    } else {
        use_mru = (psel < (1 << (PSEL_BITS - 1)));
    }

    // Streaming bypass/insertion logic
    if (is_stream) {
        // Streaming detected: insert at distant RRPV (LRU), or bypass if dead_cnt==3
        meta.rrpv = 3;
        stream_bypass++;
    } else {
        // SRRIP: insert at MRU or LRU based on set-dueling
        if (use_mru) {
            meta.rrpv = 0;
            srrip_mru_inserts++;
        } else {
            meta.rrpv = 3;
            srrip_lru_inserts++;
        }
    }

    // On victim: increment dead_cnt of victim
    if (way < LLC_WAYS) {
        size_t victim_idx = get_block_meta_idx(set, way);
        BLOCK_META &victim_meta = block_meta[victim_idx];
        if (victim_meta.dead_cnt < 3)
            victim_meta.dead_cnt++;
        if (victim_meta.dead_cnt == 3)
            dead_evictions++;
    }

    // SRRIP PSEL update: only for leader sets
    if (is_leader && !hit) {
        if (leader_type == 0) { // MRU leader
            if (psel < ((1 << PSEL_BITS) - 1)) psel++;
        } else { // LRU leader
            if (psel > 0) psel--;
        }
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "SRRIP + Streaming Bypass + Dead-Block Counter Hybrid\n";
    std::cout << "Total accesses: " << access_counter << "\n";
    std::cout << "Hits: " << hits << "\n";
    std::cout << "Streaming bypasses/inserts: " << stream_bypass << "\n";
    std::cout << "Dead-block evictions: " << dead_evictions << "\n";
    std::cout << "SRRIP MRU inserts: " << srrip_mru_inserts << "\n";
    std::cout << "SRRIP LRU inserts: " << srrip_lru_inserts << "\n";
    std::cout << "PSEL value: " << psel << "\n";
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    std::cout << "SRRIP+Streaming heartbeat: accesses=" << access_counter
              << ", hits=" << hits
              << ", stream_bypass=" << stream_bypass
              << ", srrip_mru=" << srrip_mru_inserts
              << ", srrip_lru=" << srrip_lru_inserts
              << ", dead_evictions=" << dead_evictions
              << ", PSEL=" << psel << "\n";
}