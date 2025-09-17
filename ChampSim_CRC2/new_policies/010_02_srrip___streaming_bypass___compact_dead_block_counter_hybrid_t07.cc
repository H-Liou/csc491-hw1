#include <vector>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- Per-block metadata: 2-bit RRPV, 2-bit dead-block counter ---
struct BLOCK_META {
    uint8_t rrpv;      // 2 bits
    uint8_t dead_cnt;  // 2 bits
};
std::vector<BLOCK_META> block_meta;

// --- Streaming Detector: 16-entry table per set, track last address and delta ---
struct STREAM_ENTRY {
    uint64_t last_addr;
    int64_t last_delta;
    uint8_t confidence; // 2 bits
};
#define STREAM_TABLE_SIZE 16
std::vector<STREAM_ENTRY> stream_table; // LLC_SETS * STREAM_TABLE_SIZE

// --- Statistics ---
uint64_t access_counter = 0;
uint64_t hits = 0;
uint64_t streaming_bypass = 0;
uint64_t dead_evictions = 0;
uint64_t srrip_mru_inserts = 0;
uint64_t srrip_lru_inserts = 0;

// Helper: get block meta index
inline size_t get_block_meta_idx(uint32_t set, uint32_t way) {
    return set * LLC_WAYS + way;
}

// Helper: get stream table base index for set
inline size_t get_stream_base_idx(uint32_t set) {
    return set * STREAM_TABLE_SIZE;
}

// --- Initialization ---
void InitReplacementState() {
    block_meta.resize(LLC_SETS * LLC_WAYS);
    stream_table.resize(LLC_SETS * STREAM_TABLE_SIZE);

    for (size_t i = 0; i < block_meta.size(); i++) {
        block_meta[i].rrpv = 3; // Initialize to LRU
        block_meta[i].dead_cnt = 0;
    }
    for (size_t i = 0; i < stream_table.size(); i++) {
        stream_table[i].last_addr = 0;
        stream_table[i].last_delta = 0;
        stream_table[i].confidence = 0;
    }

    access_counter = 0;
    hits = 0;
    streaming_bypass = 0;
    dead_evictions = 0;
    srrip_mru_inserts = 0;
    srrip_lru_inserts = 0;
}

// --- Victim Selection: prefer blocks with dead_cnt==3, else SRRIP (RRPV==3) ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Dead-block eviction first
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        size_t idx = get_block_meta_idx(set, way);
        if (block_meta[idx].dead_cnt == 3) {
            dead_evictions++;
            return way;
        }
    }
    // Standard SRRIP: evict block with RRPV==3
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
    // Still none: pick way 0
    return 0;
}

// --- Update Replacement State ---
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

    // --- Streaming Detector ---
    // Use STREAM_TABLE_SIZE entries per set, indexed by lower bits of paddr
    size_t stream_base = get_stream_base_idx(set);
    size_t stream_idx = stream_base + (paddr & (STREAM_TABLE_SIZE - 1));
    STREAM_ENTRY &stream = stream_table[stream_idx];

    bool is_streaming = false;
    int64_t cur_delta = 0;
    if (stream.last_addr != 0) {
        cur_delta = (int64_t)paddr - (int64_t)stream.last_addr;
        if (cur_delta == stream.last_delta && stream.confidence >= 2) {
            is_streaming = true;
        }
        // Confidence logic: saturate up if delta repeats, else decay
        if (cur_delta == stream.last_delta) {
            if (stream.confidence < 3) stream.confidence++;
        } else {
            if (stream.confidence > 0) stream.confidence--;
        }
        stream.last_delta = cur_delta;
    } else {
        stream.last_delta = 0;
    }
    stream.last_addr = paddr;

    // --- On hit ---
    if (hit) {
        meta.rrpv = 0; // Promote to MRU
        meta.dead_cnt = 0;
        hits++;
        return;
    }

    // --- On miss: insertion policy ---
    if (is_streaming) {
        // Streaming detected: insert at LRU (RRPV=3) to encourage bypass
        meta.rrpv = 3;
        streaming_bypass++;
        srrip_lru_inserts++;
    } else {
        // Standard SRRIP insertion: insert at RRPV=2 (middle), favoring moderate retention
        meta.rrpv = 2;
        srrip_mru_inserts++;
    }

    // --- On victim: increment dead_cnt ---
    if (way < LLC_WAYS) {
        size_t victim_idx = get_block_meta_idx(set, way);
        BLOCK_META &victim_meta = block_meta[victim_idx];
        if (victim_meta.dead_cnt < 3)
            victim_meta.dead_cnt++;
    }
}

// --- Print end-of-simulation statistics ---
void PrintStats() {
    std::cout << "SRRIP+StreamingBypass+DeadBlock Hybrid\n";
    std::cout << "Total accesses: " << access_counter << "\n";
    std::cout << "Hits: " << hits << "\n";
    std::cout << "Streaming bypasses: " << streaming_bypass << "\n";
    std::cout << "Dead-block evictions: " << dead_evictions << "\n";
    std::cout << "SRRIP MRU inserts: " << srrip_mru_inserts << "\n";
    std::cout << "SRRIP LRU (bypass) inserts: " << srrip_lru_inserts << "\n";
}

// --- Print periodic (heartbeat) statistics ---
void PrintStats_Heartbeat() {
    std::cout << "SRRIP+StreamingBypass heartbeat: accesses=" << access_counter
              << ", hits=" << hits
              << ", streaming_bypass=" << streaming_bypass
              << ", dead_evictions=" << dead_evictions
              << ", srrip_mru=" << srrip_mru_inserts
              << ", srrip_lru=" << srrip_lru_inserts
              << std::endl;
}