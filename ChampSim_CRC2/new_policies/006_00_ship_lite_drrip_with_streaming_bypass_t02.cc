#include <vector>
#include <cstdint>
#include <cstring>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// SHiP-lite: 6-bit signature, 2-bit outcome counter
#define SHIP_SIG_BITS 6
#define SHIP_SIG_ENTRIES 1024 // 1K entries: 6b index, 2b counter = 256B
struct SHIP_SIG_ENTRY {
    uint8_t counter; // 2 bits
};
std::vector<SHIP_SIG_ENTRY> ship_sig_table;

// Per-block: signature + RRPV
struct BLOCK_META {
    uint8_t rrpv;      // 2 bits
    uint8_t sig;       // 6 bits
};
std::vector<BLOCK_META> block_meta;

// DRRIP set-dueling
#define PSEL_BITS 10
uint16_t psel = (1 << (PSEL_BITS - 1)); // 10-bit PSEL
#define NUM_LEADER_SETS 32
std::vector<uint8_t> leader_set_type; // 0: SRRIP, 1: BRRIP

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
uint64_t ship_hits = 0;
uint64_t ship_promotes = 0;
uint64_t srip_inserts = 0;
uint64_t brip_inserts = 0;
uint64_t streaming_sets = 0;

// Helper: get block meta index
inline size_t get_block_meta_idx(uint32_t set, uint32_t way) {
    return set * LLC_WAYS + way;
}

// Helper: get SHiP signature index
inline uint32_t get_ship_sig_idx(uint64_t PC) {
    return (PC ^ (PC >> 6)) & (SHIP_SIG_ENTRIES - 1);
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
    ship_sig_table.resize(SHIP_SIG_ENTRIES);
    leader_set_type.resize(NUM_LEADER_SETS);
    stream_detector.resize(LLC_SETS);

    // Assign leader sets: evenly spaced
    for (size_t i = 0; i < NUM_LEADER_SETS; i++) {
        leader_set_type[i] = (i < NUM_LEADER_SETS / 2) ? 0 : 1; // 0:SRRIP, 1:BRRIP
    }

    for (size_t i = 0; i < block_meta.size(); i++) {
        block_meta[i].rrpv = 3; // LRU
        block_meta[i].sig = 0;
    }
    for (size_t i = 0; i < ship_sig_table.size(); i++) {
        ship_sig_table[i].counter = 1; // neutral
    }
    for (size_t i = 0; i < stream_detector.size(); i++) {
        stream_detector[i].last_addr = 0;
        memset(stream_detector[i].delta_history, 0, sizeof(stream_detector[i].delta_history));
        stream_detector[i].ptr = 0;
        stream_detector[i].streaming = false;
    }
    access_counter = 0;
    streaming_bypass = 0;
    ship_hits = 0;
    ship_promotes = 0;
    srip_inserts = 0;
    brip_inserts = 0;
    streaming_sets = 0;
}

// Victim selection: RRIP
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Prefer blocks with RRPV=3 (LRU)
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

    // Streaming detection (per set)
    update_streaming_detector(set, paddr);

    // On streaming: bypass fill (do not insert into cache)
    if (!hit && stream_detector[set].streaming) {
        meta.rrpv = 3; // mark as LRU (effectively bypass)
        streaming_bypass++;
        return;
    }

    // SHiP signature
    uint32_t sig_idx = get_ship_sig_idx(PC);

    // On cache hit
    if (hit) {
        // Promote block to MRU
        meta.rrpv = 0;
        // SHiP: increment outcome counter (max saturate)
        if (ship_sig_table[sig_idx].counter < 3)
            ship_sig_table[sig_idx].counter++;
        ship_hits++;
        ship_promotes++;
        return;
    }

    // On miss: insertion
    // DRRIP set-dueling: leader sets use fixed policy, others use PSEL
    bool is_leader = (set % (LLC_SETS / NUM_LEADER_SETS)) == 0;
    uint8_t leader_type = 0;
    if (is_leader) {
        leader_type = leader_set_type[set / (LLC_SETS / NUM_LEADER_SETS)];
    }
    bool use_brrip = false;
    if (is_leader) {
        use_brrip = (leader_type == 1);
    } else {
        use_brrip = (psel < (1 << (PSEL_BITS - 1)));
    }

    // SHiP insertion depth
    uint8_t ship_cnt = ship_sig_table[sig_idx].counter;
    uint8_t ins_rrpv = 2; // default: mid-depth
    if (ship_cnt >= 2) {
        ins_rrpv = 0; // hot PC: insert at MRU
    } else if (ship_cnt == 0) {
        ins_rrpv = 3; // cold PC: insert at LRU
    } else {
        // ins_rrpv = 2; // neutral
    }

    // DRRIP: if BRRIP, insert at RRPV=2 with 1/32 probability, else RRPV=3
    if (use_brrip) {
        if ((access_counter & 0x1F) == 0) // 1/32
            ins_rrpv = 2;
        else
            ins_rrpv = 3;
        brip_inserts++;
    } else {
        srip_inserts++;
    }

    meta.rrpv = ins_rrpv;
    meta.sig = (uint8_t)(sig_idx & ((1 << SHIP_SIG_BITS) - 1));

    // On victim: update SHiP outcome counter
    if (!hit) {
        // If victim_addr is valid, find victim's PC signature
        // For simplicity, we use the block being replaced
        size_t victim_idx = get_block_meta_idx(set, way);
        uint8_t victim_sig = block_meta[victim_idx].sig;
        if (victim_sig < SHIP_SIG_ENTRIES) {
            // If block was not reused (RRPV==3), decrement outcome counter
            if (block_meta[victim_idx].rrpv == 3) {
                if (ship_sig_table[victim_sig].counter > 0)
                    ship_sig_table[victim_sig].counter--;
            }
        }
    }

    // DRRIP PSEL update: only for leader sets
    if (is_leader && !hit) {
        if (leader_type == 0) { // SRRIP leader
            if (psel < ((1 << PSEL_BITS) - 1)) psel++;
        } else { // BRRIP leader
            if (psel > 0) psel--;
        }
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "SHiP-Lite DRRIP + Streaming Bypass\n";
    std::cout << "Total accesses: " << access_counter << "\n";
    std::cout << "Streaming bypasses: " << streaming_bypass << "\n";
    std::cout << "SHiP hits: " << ship_hits << "\n";
    std::cout << "SHiP MRU promotions: " << ship_promotes << "\n";
    std::cout << "SRRIP inserts: " << srip_inserts << "\n";
    std::cout << "BRRIP inserts: " << brip_inserts << "\n";
    std::cout << "PSEL value: " << psel << "\n";
    streaming_sets = 0;
    for (size_t i = 0; i < stream_detector.size(); i++) {
        if (stream_detector[i].streaming) streaming_sets++;
    }
    std::cout << "Streaming sets detected: " << streaming_sets << "\n";
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    std::cout << "SHiP-Lite DRRIP heartbeat: accesses=" << access_counter
              << ", streaming_bypass=" << streaming_bypass
              << ", ship_hits=" << ship_hits
              << ", ship_promotes=" << ship_promotes
              << ", srip_inserts=" << srip_inserts
              << ", brip_inserts=" << brip_inserts
              << ", PSEL=" << psel << "\n";
}