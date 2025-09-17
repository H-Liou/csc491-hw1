#include <vector>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE      1
#define LLC_SETS      (NUM_CORE * 2048)
#define LLC_WAYS      16

// RRIP parameters
static const uint8_t MAX_RRPV        = 3;
static const uint8_t INIT_RRPV       = 2;

// SHiP-lite parameters
static const uint32_t SIG_SIZE       = 1024;
static const uint32_t SIG_MASK       = (SIG_SIZE - 1);

// Streaming detector
static const uint8_t STREAM_THRESH   = 3;

// DRRIP set‐dueling parameters
static const uint32_t DUEL_PERIOD    = 64;    // stride of leader sets
static const uint32_t SR_LEADERS     = 32;    // first half are SRRIP leaders
static const uint16_t PSEL_MAX       = (1 << 10) - 1;
static const uint16_t PSEL_INIT      = (1 << 9);
static const uint16_t PSEL_THRES     = (1 << 9);

// Replacement state
static uint8_t   RRPV[LLC_SETS][LLC_WAYS];
static uint8_t   SHCT[SIG_SIZE];           // 2-bit per signature
static uint32_t  SD_last_addr[SIG_SIZE];   // streaming detector
static uint8_t   SD_count[SIG_SIZE];
static uint16_t  PSEL;                     // DRRIP policy selector

// Helper: hash PC to signature
static inline uint32_t Signature(uint64_t PC) {
    return uint32_t((PC ^ (PC >> 12)) & SIG_MASK);
}

// Victim search: standard SRRIP scan/aging
void InitReplacementState() {
    // Initialize RRPVs
    for (uint32_t s = 0; s < LLC_SETS; s++) {
        for (uint32_t w = 0; w < LLC_WAYS; w++) {
            RRPV[s][w] = MAX_RRPV;
        }
    }
    // Initialize SHCT and streaming detector
    for (uint32_t i = 0; i < SIG_SIZE; i++) {
        SHCT[i]           = 1;   // weakly neutral
        SD_last_addr[i]   = 0;
        SD_count[i]       = 0;
    }
    // Initialize DRRIP selector
    PSEL = PSEL_INIT;
}

uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // SRRIP‐style: find RRPV == MAX_RRPV, else age all
    while (true) {
        for (uint32_t w = 0; w < LLC_WAYS; w++) {
            if (RRPV[set][w] == MAX_RRPV) {
                return w;
            }
        }
        for (uint32_t w = 0; w < LLC_WAYS; w++) {
            if (RRPV[set][w] < MAX_RRPV) {
                RRPV[set][w]++;
            }
        }
    }
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
    uint32_t sig    = Signature(PC);
    uint32_t blk_id = uint32_t(paddr >> 6);

    // --- 1) Streaming detector update ---
    if (blk_id == SD_last_addr[sig] + 1) {
        if (SD_count[sig] < STREAM_THRESH) {
            SD_count[sig]++;
        }
    } else {
        SD_count[sig] = 0;
    }
    SD_last_addr[sig] = blk_id;
    bool is_stream   = (SD_count[sig] >= STREAM_THRESH);

    // Determine leader/follower for DRRIP
    bool is_sr_leader = ((set % DUEL_PERIOD) < SR_LEADERS);
    bool is_br_leader = ((set % DUEL_PERIOD) >= SR_LEADERS)
                        && ((set % DUEL_PERIOD) < (2 * SR_LEADERS));
    bool use_brrip    = false;
    if (is_sr_leader) {
        use_brrip = false;
    } else if (is_br_leader) {
        use_brrip = true;
    } else {
        use_brrip = (PSEL >= PSEL_THRES);
    }

    if (hit) {
        // On hit: strong promotion
        RRPV[set][way] = 0;
        if (SHCT[sig] < 3) {
            SHCT[sig]++;
        }
    } else {
        // Miss: decide insertion RRPV
        bool predict_reuse = (SHCT[sig] >= 2);
        uint8_t new_rrpv;

        if (is_stream) {
            // bypass‐style: very distant
            new_rrpv = MAX_RRPV;
        } else if (predict_reuse) {
            // hot PC: urgenty keep
            new_rrpv = 0;
        } else {
            // cold or uncertain PC: use DRRIP choice
            if (!use_brrip) {
                // SRRIP insertion
                new_rrpv = INIT_RRPV;
            } else {
                // BRRIP insertion: rare zero
                // use PC low bits as pseudo‐random
                if (((PC >> 4) & 0x1F) == 0) {
                    new_rrpv = 0;
                } else {
                    new_rrpv = MAX_RRPV;
                }
            }
            // punish SHCT for truly cold
            if (SHCT[sig] > 0) {
                SHCT[sig]--;
            }
        }
        RRPV[set][way] = new_rrpv;

        // Update PSEL on misses in leader sets
        if (is_sr_leader) {
            // SRRIP leader missed => favor BRRIP
            if (PSEL < PSEL_MAX) {
                PSEL++;
            }
        } else if (is_br_leader) {
            // BRRIP leader missed => favor SRRIP
            if (PSEL > 0) {
                PSEL--;
            }
        }
    }
}

void PrintStats() {
    // no statistics
}

void PrintStats_Heartbeat() {
    // no heartbeat
}