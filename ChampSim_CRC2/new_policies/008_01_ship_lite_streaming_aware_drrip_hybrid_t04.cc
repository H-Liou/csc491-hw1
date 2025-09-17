#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// DRRIP set-dueling: 32 leader sets, 10-bit PSEL
#define NUM_LEADER_SETS 32
#define PSEL_BITS 10
uint16_t psel = (1 << (PSEL_BITS - 1));
std::vector<uint8_t> leader_set_type; // 0:SRRIP, 1:BRRIP

// SHiP-lite: 6-bit PC signature per block, 2-bit outcome counter per signature (per set)
#define SIG_BITS 6
#define SIG_MASK ((1 << SIG_BITS) - 1)
struct BLOCK_META {
    uint8_t rrpv;      // 2 bits
    uint8_t sig;       // 6 bits
};
std::vector<BLOCK_META> block_meta;
struct SIG_ENTRY {
    uint8_t outcome;   // 2 bits: saturating counter, 0=dead, 3=high reuse
};
std::vector<std::vector<SIG_ENTRY>> sig_table; // [set][signature]

// Streaming detector: per-set, track last 4 address deltas, 2-bit streaming counter
struct STREAM_META {
    uint64_t last_addr;
    int64_t last_deltas[4];
    uint8_t stream_cnt; // 2 bits
};
std::vector<STREAM_META> stream_meta;

// Stats
uint64_t access_counter = 0;
uint64_t srrip_inserts = 0;
uint64_t brrip_inserts = 0;
uint64_t ship_good_inserts = 0;
uint64_t ship_bad_inserts = 0;
uint64_t stream_bypass = 0;
uint64_t hits = 0;
uint64_t stream_events = 0;
uint64_t psel_hist = 0;

// Helper: get block meta index
inline size_t get_block_meta_idx(uint32_t set, uint32_t way) {
    return set * LLC_WAYS + way;
}

// Initialization
void InitReplacementState() {
    block_meta.resize(LLC_SETS * LLC_WAYS);
    leader_set_type.resize(NUM_LEADER_SETS);
    sig_table.resize(LLC_SETS, std::vector<SIG_ENTRY>(1 << SIG_BITS));
    stream_meta.resize(LLC_SETS);

    // Assign leader sets: evenly spaced
    for (size_t i = 0; i < NUM_LEADER_SETS; i++) {
        leader_set_type[i] = (i < NUM_LEADER_SETS / 2) ? 0 : 1; // 0:SRRIP, 1:BRRIP
    }

    for (size_t i = 0; i < block_meta.size(); i++) {
        block_meta[i].rrpv = 3; // LRU
        block_meta[i].sig = 0;
    }
    for (size_t s = 0; s < LLC_SETS; s++) {
        for (size_t j = 0; j < (1 << SIG_BITS); j++)
            sig_table[s][j].outcome = 1; // neutral
        stream_meta[s].last_addr = 0;
        for (int d = 0; d < 4; d++)
            stream_meta[s].last_deltas[d] = 0;
        stream_meta[s].stream_cnt = 0;
    }

    access_counter = 0;
    srrip_inserts = 0;
    brrip_inserts = 0;
    ship_good_inserts = 0;
    ship_bad_inserts = 0;
    stream_bypass = 0;
    hits = 0;
    stream_events = 0;
    psel_hist = 0;
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
    // Standard RRIP victim selection
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; way++) {
            size_t idx = get_block_meta_idx(set, way);
            if (block_meta[idx].rrpv == 3)
                return way;
        }
        // Increment RRPVs
        for (uint32_t way = 0; way < LLC_WAYS; way++) {
            size_t idx = get_block_meta_idx(set, way);
            if (block_meta[idx].rrpv < 3)
                block_meta[idx].rrpv++;
        }
    }
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

    // Streaming detector: track address deltas
    STREAM_META &stream = stream_meta[set];
    int64_t delta = (stream.last_addr == 0) ? 0 : (int64_t)paddr - (int64_t)stream.last_addr;
    stream.last_addr = paddr;
    // Update delta history
    for (int d = 3; d > 0; d--)
        stream.last_deltas[d] = stream.last_deltas[d - 1];
    stream.last_deltas[0] = delta;
    // Streaming pattern: if last 4 deltas are equal and nonzero, increment stream_cnt
    bool streaming = false;
    if (delta != 0 &&
        stream.last_deltas[0] == stream.last_deltas[1] &&
        stream.last_deltas[1] == stream.last_deltas[2] &&
        stream.last_deltas[2] == stream.last_deltas[3]) {
        if (stream.stream_cnt < 3) stream.stream_cnt++;
        streaming = (stream.stream_cnt >= 2);
        if (streaming) stream_events++;
    } else {
        if (stream.stream_cnt > 0) stream.stream_cnt--;
    }

    // SHiP-lite signature
    uint8_t sig = champsim_crc2(PC) & SIG_MASK;
    SIG_ENTRY &sig_entry = sig_table[set][sig];

    // On hit: promote block to MRU, update SHiP outcome
    if (hit) {
        meta.rrpv = 0;
        if (sig_entry.outcome < 3)
            sig_entry.outcome++;
        hits++;
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

    // Streaming-aware bypass/insertion
    if (streaming) {
        // Insert at distant RRPV, or bypass with small probability
        if ((access_counter & 0x1F) == 0) { // 1/32: bypass
            stream_bypass++;
            // Do not update block meta: simulate bypass
            return;
        } else {
            meta.rrpv = 3; // LRU
        }
    } else {
        // SHiP outcome: if signature outcome==0, insert at LRU (dead), else DRRIP policy
        if (sig_entry.outcome == 0) {
            meta.rrpv = 3;
            ship_bad_inserts++;
        } else {
            if (use_brrip) {
                // BRRIP: insert at RRPV=2 (long re-reference interval) with 1/32 probability, else RRPV=3
                if ((access_counter & 0x1F) == 0)
                    meta.rrpv = 2;
                else
                    meta.rrpv = 3;
                brrip_inserts++;
            } else {
                // SRRIP: insert at RRPV=2
                meta.rrpv = 2;
                srrip_inserts++;
            }
            ship_good_inserts++;
        }
    }
    meta.sig = sig;

    // On victim: update SHiP outcome for signature of evicted block
    size_t victim_idx = get_block_meta_idx(set, way);
    uint8_t victim_sig = block_meta[victim_idx].sig;
    SIG_ENTRY &victim_entry = sig_table[set][victim_sig];
    if (victim_entry.outcome > 0)
        victim_entry.outcome--;

    // DRRIP PSEL update: only for leader sets
    if (is_leader && !hit) {
        if (leader_type == 0) { // SRRIP leader
            if (psel < ((1 << PSEL_BITS) - 1)) psel++;
        } else { // BRRIP leader
            if (psel > 0) psel--;
        }
        psel_hist = psel;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "SHiP-Lite Streaming-Aware DRRIP Hybrid\n";
    std::cout << "Total accesses: " << access_counter << "\n";
    std::cout << "Hits: " << hits << "\n";
    std::cout << "SRRIP inserts: " << srrip_inserts << "\n";
    std::cout << "BRRIP inserts: " << brrip_inserts << "\n";
    std::cout << "SHiP good inserts: " << ship_good_inserts << "\n";
    std::cout << "SHiP bad inserts: " << ship_bad_inserts << "\n";
    std::cout << "Streaming bypasses: " << stream_bypass << "\n";
    std::cout << "Streaming events: " << stream_events << "\n";
    std::cout << "PSEL value: " << psel_hist << "\n";
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    std::cout << "SHiP-Lite Streaming-Aware DRRIP heartbeat: accesses=" << access_counter
              << ", hits=" << hits
              << ", srrip_inserts=" << srrip_inserts
              << ", brrip_inserts=" << brrip_inserts
              << ", ship_good_inserts=" << ship_good_inserts
              << ", ship_bad_inserts=" << ship_bad_inserts
              << ", stream_bypass=" << stream_bypass
              << ", stream_events=" << stream_events
              << ", PSEL=" << psel_hist << "\n";
}