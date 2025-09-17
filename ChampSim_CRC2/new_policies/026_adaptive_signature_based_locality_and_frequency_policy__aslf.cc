#include <vector>
#include <cstdint>
#include <iostream>
#include <algorithm>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// RRIP constants
#define RRIP_BITS 2
#define RRIP_MAX ((1 << RRIP_BITS) - 1)
#define RRIP_LONG 0
#define RRIP_SHORT RRIP_MAX

// Signature tracking
#define SIG_TABLE_SIZE 4 // Number of recent signatures per set
#define SIG_BITS 12      // Signature width (address + PC bits)

// Frequency tracking
#define FREQ_MAX 7

struct BlockMeta {
    uint8_t valid;
    uint8_t rrip;
    uint64_t tag;
    uint8_t freq; // frequency counter
    uint16_t signature; // signature of block
};

struct SetState {
    std::vector<BlockMeta> meta;
    std::vector<uint16_t> recent_signatures; // signature history
};

std::vector<SetState> sets(LLC_SETS);

// --- Helper: compute block signature ---
inline uint16_t compute_signature(uint64_t paddr, uint64_t PC) {
    // Use address bits [12:6] and PC bits [7:2]
    uint16_t addr_sig = (paddr >> 6) & 0x7F; // 7 bits
    uint16_t pc_sig = (PC >> 2) & 0x3F;      // 6 bits
    return (addr_sig << 6) | pc_sig;         // 13 bits, truncate to 12
}

// --- Initialize replacement state ---
void InitReplacementState() {
    for (auto& set : sets) {
        set.meta.assign(LLC_WAYS, {0, RRIP_MAX, 0, 0, 0});
        set.recent_signatures.assign(SIG_TABLE_SIZE, 0);
    }
}

// --- Find victim in the set ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    SetState& s = sets[set];

    // Prefer invalid blocks
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        if (!current_set[way].valid)
            return way;
    }

    // Evict RRIP_MAX block with lowest frequency
    uint32_t victim = 0;
    uint8_t max_rrip = 0, min_freq = FREQ_MAX+1;
    bool found = false;
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        if (s.meta[way].rrip == RRIP_MAX) {
            if (!found || s.meta[way].freq < min_freq) {
                victim = way;
                min_freq = s.meta[way].freq;
                found = true;
            }
        }
    }
    if (found)
        return victim;

    // Aging: increment RRIP, decay freq
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        s.meta[way].rrip = std::min<uint8_t>(RRIP_MAX, s.meta[way].rrip + 1);
        if (s.meta[way].freq > 0)
            s.meta[way].freq--;
    }

    // Fallback: evict block with maximal RRIP value and lowest freq
    victim = 0;
    max_rrip = 0;
    min_freq = FREQ_MAX+1;
    for (uint32_t way = 0; way < LLC_WAYS; way++) {
        if (s.meta[way].rrip >= max_rrip) {
            if (s.meta[way].freq < min_freq) {
                max_rrip = s.meta[way].rrip;
                min_freq = s.meta[way].freq;
                victim = way;
            }
        }
    }
    return victim;
}

// --- Update replacement state ---
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
    SetState& s = sets[set];
    uint64_t tag = paddr >> 6;
    uint16_t sig = compute_signature(paddr, PC);

    if (hit) {
        // On hit: reset RRIP, bump frequency, update signature
        s.meta[way].rrip = RRIP_LONG;
        if (s.meta[way].freq < FREQ_MAX)
            s.meta[way].freq++;
        s.meta[way].signature = sig;
        // Update signature table
        auto it = std::find(s.recent_signatures.begin(), s.recent_signatures.end(), sig);
        if (it == s.recent_signatures.end()) {
            s.recent_signatures.pop_back();
            s.recent_signatures.insert(s.recent_signatures.begin(), sig);
        }
    } else {
        // On miss/insertion: signature and frequency based insertion
        bool sig_match = std::find(s.recent_signatures.begin(), s.recent_signatures.end(), sig) != s.recent_signatures.end();
        uint8_t insert_rrip = RRIP_SHORT;
        if (sig_match) {
            insert_rrip = RRIP_LONG; // spatial locality
        } else {
            // If any block in set has freq >= FREQ_MAX-1, promote retention
            for (uint32_t w = 0; w < LLC_WAYS; w++) {
                if (s.meta[w].freq >= FREQ_MAX-1) {
                    insert_rrip = RRIP_LONG;
                    break;
                }
            }
        }
        s.meta[way].valid = 1;
        s.meta[way].tag = tag;
        s.meta[way].rrip = insert_rrip;
        s.meta[way].freq = sig_match ? FREQ_MAX/2 : 0;
        s.meta[way].signature = sig;

        // Update signature table
        auto it = std::find(s.recent_signatures.begin(), s.recent_signatures.end(), sig);
        if (it == s.recent_signatures.end()) {
            s.recent_signatures.pop_back();
            s.recent_signatures.insert(s.recent_signatures.begin(), sig);
        }
    }
}

// --- Stats ---
uint64_t total_hits = 0, total_misses = 0, total_evictions = 0;
void PrintStats() {
    std::cout << "ASLF: Hits=" << total_hits << " Misses=" << total_misses
              << " Evictions=" << total_evictions << std::endl;
}
void PrintStats_Heartbeat() {
    PrintStats();
}