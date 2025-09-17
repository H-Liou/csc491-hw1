#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// SHiP-lite: 6-bit PC signature, 2-bit outcome counter (per-PC)
// 2048 sets * 16 ways = 32768 blocks; signature table size: 1024 entries
#define SIGNATURE_BITS 6
#define SIGNATURE_TABLE_SIZE 1024
struct SignatureEntry {
    uint8_t reuse_count; // 2 bits
};
std::vector<SignatureEntry> signature_table;

// Per-block metadata: RRPV (2 bits), signature (6 bits)
struct BLOCK_META {
    uint8_t rrpv;         // 2 bits
    uint8_t signature;    // 6 bits
};
std::vector<BLOCK_META> block_meta;

// DRRIP: Set-dueling (32 leader sets), 10-bit PSEL
#define NUM_LEADER_SETS 32
#define PSEL_BITS 10
uint16_t psel = (1 << (PSEL_BITS - 1));
std::vector<uint8_t> leader_set_type; // 0:SRRIP, 1:BRRIP

// Streaming detector: per-set, 2-bit streaming counter, last paddr
struct STREAM_DETECT {
    uint64_t last_paddr;
    uint8_t stream_cnt; // 2 bits: saturates up if streaming fills, down on hit
};
std::vector<STREAM_DETECT> stream_state;

// Stats
uint64_t access_counter = 0;
uint64_t hits = 0;
uint64_t bypassed_fills = 0;
uint64_t streaming_events = 0;
uint64_t ship_mru_inserts = 0;
uint64_t ship_lru_inserts = 0;
uint64_t drrip_srrip_inserts = 0;
uint64_t drrip_brrip_inserts = 0;

inline size_t get_block_meta_idx(uint32_t set, uint32_t way) {
    return set * LLC_WAYS + way;
}
inline size_t get_signature_idx(uint64_t PC) {
    return champsim_crc2(PC, 0) % SIGNATURE_TABLE_SIZE;
}
inline bool is_leader_set(uint32_t set) {
    return (set % (LLC_SETS / NUM_LEADER_SETS)) == 0;
}

void InitReplacementState() {
    block_meta.resize(LLC_SETS * LLC_WAYS);
    signature_table.resize(SIGNATURE_TABLE_SIZE);
    leader_set_type.resize(NUM_LEADER_SETS);
    stream_state.resize(LLC_SETS);

    // Leader sets: half SRRIP, half BRRIP
    for (size_t i = 0; i < NUM_LEADER_SETS; i++)
        leader_set_type[i] = (i < NUM_LEADER_SETS / 2) ? 0 : 1;
    for (size_t i = 0; i < block_meta.size(); i++) {
        block_meta[i].rrpv = 3;
        block_meta[i].signature = 0;
    }
    for (size_t i = 0; i < signature_table.size(); i++)
        signature_table[i].reuse_count = 1;
    for (size_t i = 0; i < stream_state.size(); i++) {
        stream_state[i].last_paddr = 0;
        stream_state[i].stream_cnt = 0;
    }

    psel = (1 << (PSEL_BITS - 1));
    access_counter = 0;
    hits = 0;
    bypassed_fills = 0;
    streaming_events = 0;
    ship_mru_inserts = 0;
    ship_lru_inserts = 0;
    drrip_srrip_inserts = 0;
    drrip_brrip_inserts = 0;
}

// Victim selection: SRRIP/BRRIP style
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Streaming bypass: If streaming detected, always pick way 0 (will be overwritten, not cached)
    if (stream_state[set].stream_cnt == 3)
        return 0;

    // Otherwise: SRRIP victim selection (prefer RRPV==3, else increment and retry)
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; way++) {
            size_t idx = get_block_meta_idx(set, way);
            if (block_meta[idx].rrpv == 3)
                return way;
        }
        // No candidate found, increment all RRPVs and retry
        for (uint32_t way = 0; way < LLC_WAYS; way++) {
            size_t idx = get_block_meta_idx(set, way);
            if (block_meta[idx].rrpv < 3)
                block_meta[idx].rrpv++;
        }
    }
    return 0;
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
    size_t idx = get_block_meta_idx(set, way);
    BLOCK_META &meta = block_meta[idx];

    // Streaming detector: look for sequential fills and no hits
    uint64_t last_addr = stream_state[set].last_paddr;
    uint64_t delta = (last_addr != 0) ? paddr - last_addr : 0;
    bool streaming_fill = (!hit) && (delta == 64); // 64B line stride
    if (streaming_fill)
        stream_state[set].stream_cnt = (stream_state[set].stream_cnt < 3) ? stream_state[set].stream_cnt + 1 : 3;
    else if (hit && stream_state[set].stream_cnt > 0)
        stream_state[set].stream_cnt--;
    stream_state[set].last_paddr = paddr;

    // If streaming detected, bypass future fills (don't cache)
    if (!hit && stream_state[set].stream_cnt == 3) {
        bypassed_fills++;
        streaming_events++;
        // No insertion: don't update RRPV, don't cache block (simulate bypass)
        return;
    }

    // SHiP-lite: track PC signature
    size_t sig_idx = get_signature_idx(PC);
    uint8_t sig = PC & ((1 << SIGNATURE_BITS) - 1);
    meta.signature = sig;

    if (hit) {
        meta.rrpv = 0;
        if (signature_table[sig_idx].reuse_count < 3)
            signature_table[sig_idx].reuse_count++;
        hits++;
        return;
    }

    // Insertion: Use SHiP outcome counter to choose MRU/LRU, else DRRIP
    uint8_t reuse = signature_table[sig_idx].reuse_count;
    bool ship_mru = (reuse >= 2);

    // DRRIP set-dueling
    bool is_leader = is_leader_set(set);
    uint8_t leader_type = is_leader ? leader_set_type[set / (LLC_SETS / NUM_LEADER_SETS)] : 0;
    bool use_brrip = false;
    if (is_leader) {
        use_brrip = (leader_type == 1);
    } else {
        use_brrip = (psel < (1 << (PSEL_BITS - 1)));
    }

    if (ship_mru) {
        meta.rrpv = 0;
        ship_mru_inserts++;
    } else {
        meta.rrpv = 3;
        ship_lru_inserts++;
    }

    // If SHiP does not bias MRU (reuse < 2), fall back to DRRIP
    if (!ship_mru) {
        if (use_brrip) {
            // BRRIP: Insert at RRPV=2 (long re-reference)
            meta.rrpv = ((access_counter & 0x1F) == 0) ? 0 : 2;
            drrip_brrip_inserts++;
        } else {
            // SRRIP: Insert at RRPV=2
            meta.rrpv = 2;
            drrip_srrip_inserts++;
        }
    }

    // Update SHiP outcome on victim (if evicted block's signature is present)
    size_t victim_sig_idx = get_signature_idx(PC);
    if (signature_table[victim_sig_idx].reuse_count > 0 && !hit)
        signature_table[victim_sig_idx].reuse_count--;

    // DRRIP: PSEL update for leader sets (only on misses)
    if (is_leader && !hit) {
        if (leader_type == 0) { // SRRIP leader
            if (psel < ((1 << PSEL_BITS) - 1)) psel++;
        } else { // BRRIP leader
            if (psel > 0) psel--;
        }
    }
}

void PrintStats() {
    std::cout << "SHiP-Lite Streaming-Bypass DRRIP Hybrid\n";
    std::cout << "Total accesses: " << access_counter << "\n";
    std::cout << "Hits: " << hits << "\n";
    std::cout << "Bypassed fills: " << bypassed_fills << "\n";
    std::cout << "Streaming events: " << streaming_events << "\n";
    std::cout << "SHiP MRU inserts: " << ship_mru_inserts << "\n";
    std::cout << "SHiP LRU inserts: " << ship_lru_inserts << "\n";
    std::cout << "DRRIP SRRIP inserts: " << drrip_srrip_inserts << "\n";
    std::cout << "DRRIP BRRIP inserts: " << drrip_brrip_inserts << "\n";
    std::cout << "PSEL value: " << psel << "\n";
}

void PrintStats_Heartbeat() {
    std::cout << "SHiP-Lite Streaming-Bypass heartbeat: accesses=" << access_counter
              << ", hits=" << hits
              << ", bypassed_fills=" << bypassed_fills
              << ", streaming_events=" << streaming_events
              << ", ship_mru_inserts=" << ship_mru_inserts
              << ", ship_lru_inserts=" << ship_lru_inserts
              << ", drrip_srrip_inserts=" << drrip_srrip_inserts
              << ", drrip_brrip_inserts=" << drrip_brrip_inserts
              << ", PSEL=" << psel << "\n";
}