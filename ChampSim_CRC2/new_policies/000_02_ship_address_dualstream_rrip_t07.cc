#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- Metadata sizes ---
// 2 bits RRPV per block
// 2 bits dead-block counter per block
// 6 bits SHiP signature per block
// 2 bits SHiP outcome per signature entry
// 4 bits per-set address delta stream detector
// 10 bits global PSEL
// 32 leader sets per policy

// --- Replacement State ---
struct BlockMeta {
    uint8_t rrpv;        // 2 bits
    uint8_t dead_ctr;    // 2 bits
    uint8_t ship_sig;    // 6 bits
};

BlockMeta repl_meta[LLC_SETS][LLC_WAYS];

// SHiP signature table: 2048 entries, 2 bits each = 4096 bits = 0.5 KiB
uint8_t ship_outcome[2048]; // 2 bits per entry

// Streaming detector: 4 bits per set = 8192 bits = 1 KiB
uint8_t stream_hist[LLC_SETS];

// DIP set-dueling
#define NUM_LEADER_SETS 32
uint8_t is_srrip_leader[LLC_SETS];
uint8_t is_brrip_leader[LLC_SETS];

// 10-bit PSEL
uint16_t psel = 512;

// Helper: Map PC to SHiP signature
inline uint16_t get_ship_sig(uint64_t PC) {
    return (PC ^ (PC >> 2)) & 0x3F; // 6 bits
}

// Helper: Map set to SHiP outcome table
inline uint16_t get_ship_index(uint16_t sig) {
    return sig ^ (sig << 3) ^ (sig << 1);
}

// Helper: Map set to streaming history
inline uint16_t get_stream_index(uint32_t set) {
    return set;
}

void InitReplacementState() {
    // Init per-block metadata
    for(uint32_t set=0; set<LLC_SETS; set++) {
        for(uint32_t way=0; way<LLC_WAYS; way++) {
            repl_meta[set][way].rrpv = 3; // distant
            repl_meta[set][way].dead_ctr = 0;
            repl_meta[set][way].ship_sig = 0;
        }
        stream_hist[set] = 0;
        is_srrip_leader[set] = 0;
        is_brrip_leader[set] = 0;
    }
    // Leader sets for DIP
    for(uint32_t i=0; i<NUM_LEADER_SETS; i++) {
        is_srrip_leader[i] = 1;
        is_brrip_leader[LLC_SETS-NUM_LEADER_SETS+i] = 1;
    }
    // SHiP outcome
    memset(ship_outcome, 0, sizeof(ship_outcome));
    psel = 512;
}

uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Streaming detector: check recent address delta
    uint8_t stream_conf = stream_hist[set] >> 2; // top 2 bits
    bool is_streaming = (stream_conf >= 2);

    // Dead-block aware victim selection
    uint32_t victim = LLC_WAYS;
    // Prefer blocks with dead_ctr==3, then RRPV==3
    for(uint32_t way=0; way<LLC_WAYS; way++) {
        if(repl_meta[set][way].dead_ctr == 3) {
            victim = way;
            break;
        }
    }
    if(victim == LLC_WAYS) {
        // No dead block, fall back to RRPV==3
        for(uint32_t way=0; way<LLC_WAYS; way++) {
            if(repl_meta[set][way].rrpv == 3) {
                victim = way;
                break;
            }
        }
    }
    // If still not found, increment all RRPVs and retry
    if(victim == LLC_WAYS) {
        for(uint32_t way=0; way<LLC_WAYS; way++)
            repl_meta[set][way].rrpv = std::min(repl_meta[set][way].rrpv+1, (uint8_t)3);
        // Retry
        for(uint32_t way=0; way<LLC_WAYS; way++) {
            if(repl_meta[set][way].rrpv == 3) {
                victim = way;
                break;
            }
        }
    }
    if(victim == LLC_WAYS) victim = 0; // Fallback

    return victim;
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
    // Streaming detector update
    uint16_t idx = get_stream_index(set);
    uint64_t addr_tag = paddr >> 6; // block addr
    static uint64_t last_addr[LLC_SETS] = {0};
    int64_t delta = addr_tag - last_addr[idx];
    last_addr[idx] = addr_tag;
    // Keep low 2 bits for stride pattern (wrap-around)
    uint8_t old_hist = stream_hist[idx] & 0xF;
    if(std::abs(delta) == 1 && delta != 0) {
        // Monotonic stride detected
        stream_hist[idx] = (old_hist << 1) | 1;
    } else {
        stream_hist[idx] = (old_hist << 1);
    }
    // Keep top 2 bits as streaming confidence
    stream_hist[idx] &= 0xF;

    // SHiP signature
    uint16_t sig = get_ship_sig(PC);
    uint16_t ship_idx = sig;
    // Dead-block counter decay (every 128K accesses)
    static uint64_t access_count = 0;
    access_count++;
    if((access_count & 0x1FFFF) == 0) { // every 128K
        for(uint32_t s=0; s<LLC_SETS; s++)
            for(uint32_t w=0; w<LLC_WAYS; w++)
                repl_meta[s][w].dead_ctr = repl_meta[s][w].dead_ctr >> 1;
    }

    // DIP set-dueling
    bool use_srrip = false;
    if(is_srrip_leader[set]) use_srrip = true;
    else if(is_brrip_leader[set]) use_srrip = false;
    else use_srrip = (psel >= 512);

    // On cache fill (miss)
    if(!hit) {
        // Streaming detected? If so, bypass or insert distant
        uint8_t stream_conf = stream_hist[set] >> 2;
        bool is_streaming = (stream_conf >= 2);

        // SHiP outcome
        uint8_t outcome = ship_outcome[ship_idx] & 0x3;

        // Dead-block prediction: If last block evicted w/o reuse, dead_ctr++
        repl_meta[set][way].dead_ctr = std::min((uint8_t)(repl_meta[set][way].dead_ctr+1), (uint8_t)3);

        // Insert: Streaming? Insert at distant (RRPV=3), else SHiP outcome
        if(is_streaming) {
            repl_meta[set][way].rrpv = 3; // distant
        } else {
            // If SHiP outcome strong (>=2), insert at RRPV=1 (protected)
            // If weak outcome (0/1), insert at RRPV=2 or 3
            if(outcome >= 2) repl_meta[set][way].rrpv = use_srrip ? 1 : 2;
            else repl_meta[set][way].rrpv = 3;
        }
        // Save SHiP signature
        repl_meta[set][way].ship_sig = sig;
    } else {
        // Hit: reward reuse
        repl_meta[set][way].rrpv = 0;
        // Reward SHiP outcome
        uint16_t ship_idx = repl_meta[set][way].ship_sig;
        if(ship_outcome[ship_idx] < 3) ship_outcome[ship_idx]++;
        // Reset dead-block counter
        repl_meta[set][way].dead_ctr = 0;
    }

    // On eviction, if block was not reused, penalize SHiP outcome
    static uint64_t last_evicted_addr[LLC_SETS][LLC_WAYS] = {{0}};
    static uint8_t was_reused[LLC_SETS][LLC_WAYS] = {{0}};
    // Mark as not reused on fill
    if(!hit) {
        last_evicted_addr[set][way] = paddr;
        was_reused[set][way] = 0;
    }
    // On hit, mark as reused
    if(hit) {
        was_reused[set][way] = 1;
    }
    // When a block is chosen as victim (in GetVictimInSet), in next fill, penalize old SHiP outcome
    // Here, if dead_ctr==3, decay SHiP outcome
    if(repl_meta[set][way].dead_ctr == 3) {
        uint16_t old_sig = repl_meta[set][way].ship_sig;
        if(ship_outcome[old_sig] > 0) ship_outcome[old_sig]--;
    }

    // DIP PSEL update (only on leader sets)
    if(!hit) {
        if(is_srrip_leader[set] && hit) { if(psel < 1023) psel++; }
        if(is_brrip_leader[set] && hit) { if(psel > 0) psel--; }
    }
}

void PrintStats() {
    // No-op for this template
}
void PrintStats_Heartbeat() {
    // No-op for this template
}