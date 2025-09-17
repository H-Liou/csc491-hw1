#include <vector>
#include <cstdint>
#include <cstring>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// DIP set-dueling
#define PSEL_BITS 10
uint16_t psel = (1 << (PSEL_BITS - 1)); // 10-bit PSEL
#define NUM_LEADER_SETS 32
std::vector<uint8_t> leader_set_type; // 0: LIP, 1: BIP

// Dead-block predictor: 2-bit reuse counter per block
struct BLOCK_META {
    uint8_t reuse_counter; // 2 bits
    uint8_t lru_position;  // 4 bits
};
std::vector<BLOCK_META> block_meta;

// Streaming detector: per set
#define STREAM_DELTA_HISTORY 4
#define STREAM_DELTA_THRESHOLD 3
struct STREAM_DETECTOR {
    uint64_t last_addr;
    int64_t delta_history[STREAM_DELTA_HISTORY];
    uint8_t ptr;
    bool streaming;
};
std::vector<STREAM_DETECTOR> stream_detector;

// Stats
uint64_t access_counter = 0;
uint64_t streaming_bypass = 0;
uint64_t hits = 0;
uint64_t lip_inserts = 0;
uint64_t bip_inserts = 0;
uint64_t dead_inserts = 0;
uint64_t streaming_sets = 0;

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

// Initialization
void InitReplacementState() {
    block_meta.resize(LLC_SETS * LLC_WAYS);
    leader_set_type.resize(NUM_LEADER_SETS);
    stream_detector.resize(LLC_SETS);

    // Assign leader sets: evenly spaced
    for (size_t i = 0; i < NUM_LEADER_SETS; i++) {
        leader_set_type[i] = (i < NUM_LEADER_SETS / 2) ? 0 : 1; // 0:LIP, 1:BIP
    }

    for (size_t i = 0; i < block_meta.size(); i++) {
        block_meta[i].reuse_counter = 1; // neutral
        block_meta[i].lru_position = LLC_WAYS - 1;
    }
    for (size_t i = 0; i < stream_detector.size(); i++) {
        stream_detector[i].last_addr = 0;
        memset(stream_detector[i].delta_history, 0, sizeof(stream_detector[i].delta_history));
        stream_detector[i].ptr = 0;
        stream_detector[i].streaming = false;
    }
    access_counter = 0;
    streaming_bypass = 0;
    hits = 0;
    lip_inserts = 0;
    bip_inserts = 0;
    dead_inserts = 0;
    streaming_sets = 0;
}

// Find victim in the set (LRU)
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Find block with max lru_position (the LRU)
    uint32_t victim = 0;
    uint8_t max_lru = 0;
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        size_t idx = get_block_meta_idx(set, way);
        if (block_meta[idx].lru_position >= max_lru) {
            max_lru = block_meta[idx].lru_position;
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

    // On streaming: bypass fill
    if (!hit && stream_detector[set].streaming) {
        meta.lru_position = LLC_WAYS - 1; // Mark as LRU (effectively bypass)
        streaming_bypass++;
        return;
    }

    // On cache hit
    if (hit) {
        // Promote block to MRU
        uint8_t old_lru = meta.lru_position;
        for (uint32_t w = 0; w < LLC_WAYS; w++) {
            size_t idx2 = get_block_meta_idx(set, w);
            if (block_meta[idx2].lru_position < old_lru)
                block_meta[idx2].lru_position++;
        }
        meta.lru_position = 0;

        // Dead-block predictor: increment reuse counter (max saturate)
        if (meta.reuse_counter < 3)
            meta.reuse_counter++;
        hits++;
        return;
    }

    // On miss: insertion
    // DIP set-dueling: leader sets use fixed policy, others use PSEL
    bool is_leader = (set % (LLC_SETS / NUM_LEADER_SETS)) == 0;
    uint8_t leader_type = 0;
    if (is_leader)
        leader_type = leader_set_type[set / (LLC_SETS / NUM_LEADER_SETS)];

    // Choose LIP/BIP for insertion
    bool use_bip = false;
    if (is_leader)
        use_bip = (leader_type == 1);
    else
        use_bip = (psel < (1 << (PSEL_BITS - 1)));

    // Dead-block predictor: insert at MRU if reused, else LRU
    uint8_t ins_lru = LLC_WAYS - 1; // default LRU
    if (meta.reuse_counter >= 2) {
        ins_lru = 0; // predicted live, MRU
    } else if (meta.reuse_counter == 0) {
        ins_lru = LLC_WAYS - 1; // predicted dead, LRU
        dead_inserts++;
    }

    // DIP: if BIP, insert at MRU with 1/32 probability, else LRU
    if (use_bip) {
        if ((access_counter & 0x1F) == 0)
            ins_lru = 0;
        else
            ins_lru = LLC_WAYS - 1;
        bip_inserts++;
    } else {
        lip_inserts++;
    }

    // Update LRU positions for insertion
    for (uint32_t w = 0; w < LLC_WAYS; w++) {
        size_t idx2 = get_block_meta_idx(set, w);
        if (block_meta[idx2].lru_position < ins_lru)
            block_meta[idx2].lru_position++;
    }
    meta.lru_position = ins_lru;
    meta.reuse_counter = 1; // set neutral for new block

    // On victim: update dead-block predictor for replaced block
    if (!hit) {
        size_t victim_idx = get_block_meta_idx(set, way);
        if (block_meta[victim_idx].lru_position == (LLC_WAYS - 1)) {
            // Block was not reused, decrement reuse counter
            if (block_meta[victim_idx].reuse_counter > 0)
                block_meta[victim_idx].reuse_counter--;
        }
    }

    // DIP PSEL update: only for leader sets
    if (is_leader && !hit) {
        if (leader_type == 0) { // LIP leader
            if (psel < ((1 << PSEL_BITS) - 1)) psel++;
        } else { // BIP leader
            if (psel > 0) psel--;
        }
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "DIP-Deadblock + Streaming Bypass\n";
    std::cout << "Total accesses: " << access_counter << "\n";
    std::cout << "Streaming bypasses: " << streaming_bypass << "\n";
    std::cout << "Hits: " << hits << "\n";
    std::cout << "LIP inserts: " << lip_inserts << "\n";
    std::cout << "BIP inserts: " << bip_inserts << "\n";
    std::cout << "Deadblock inserts: " << dead_inserts << "\n";
    std::cout << "PSEL value: " << psel << "\n";
    streaming_sets = 0;
    for (size_t i = 0; i < stream_detector.size(); i++) {
        if (stream_detector[i].streaming) streaming_sets++;
    }
    std::cout << "Streaming sets detected: " << streaming_sets << "\n";
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    std::cout << "DIP-Deadblock heartbeat: accesses=" << access_counter
              << ", streaming_bypass=" << streaming_bypass
              << ", hits=" << hits
              << ", lip_inserts=" << lip_inserts
              << ", bip_inserts=" << bip_inserts
              << ", dead_inserts=" << dead_inserts
              << ", PSEL=" << psel << "\n";
}