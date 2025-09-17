#include <vector>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE       1
#define LLC_SETS       (NUM_CORE * 2048)
#define LLC_WAYS       16
#define MAX_RRPV       3      // 2-bit RRPV: [0..3]
#define INIT_RRPV      MAX_RRPV
#define SHIP_BITS      13     // 8K entries
#define SHIP_SIZE      (1 << SHIP_BITS)
#define SHIP_MAX       7      // 3-bit counter: [0..7]
#define SHIP_THRESHOLD 4      // >=4 => hot
#define STR_BITS       9      // 512 entries
#define STR_SIZE       (1 << STR_BITS)
#define STR_MAX        3      // 2-bit saturating: [0..3]
#define STR_THRES      2      // >=2 => streaming
#define LINE_SIZE      64ULL

// Per-line RRPV
static uint8_t RRPV[LLC_SETS][LLC_WAYS];

// SHiP signature table
static uint8_t SigTable[SHIP_SIZE];

// Streaming detector tables
static uint32_t StrLastPA[STR_SIZE];
static int8_t   StrLastDelta[STR_SIZE];
static uint8_t  StrCnt[STR_SIZE];

// Hash helpers
static inline uint32_t PC2Sig(uint64_t PC) {
    // mix bits to index SHiP table
    return uint32_t((PC ^ (PC >> 15)) & (SHIP_SIZE - 1));
}
static inline uint32_t PC2Str(uint64_t PC) {
    return uint32_t((PC ^ (PC >> 13)) & (STR_SIZE - 1));
}

void InitReplacementState() {
    // Initialize RRPVs
    for (uint32_t s = 0; s < LLC_SETS; s++) {
        for (uint32_t w = 0; w < LLC_WAYS; w++) {
            RRPV[s][w] = INIT_RRPV;
        }
    }
    // Initialize signature counters to weak reuse
    for (uint32_t i = 0; i < SHIP_SIZE; i++) {
        SigTable[i] = SHIP_THRESHOLD / 2;
    }
    // Initialize stream detectors
    for (uint32_t i = 0; i < STR_SIZE; i++) {
        StrLastPA[i]    = 0;
        StrLastDelta[i] = 0;
        StrCnt[i]       = STR_THRES; // start neutral
    }
}

uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Find any block with RRPV == MAX_RRPV
    while (true) {
        for (uint32_t w = 0; w < LLC_WAYS; w++) {
            if (RRPV[set][w] == MAX_RRPV) {
                return w;
            }
        }
        // age all blocks
        for (uint32_t w = 0; w < LLC_WAYS; w++) {
            if (RRPV[set][w] < MAX_RRPV)
                RRPV[set][w]++;
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
    uint32_t s_sig = PC2Sig(PC);
    uint32_t s_str = PC2Str(PC);

    if (hit) {
        // On hit: MRU and train signature
        RRPV[set][way] = 0;
        if (SigTable[s_sig] < SHIP_MAX) SigTable[s_sig]++;
        return;
    }

    // MISS --------------------------------------------------------
    // 1) Update streaming detector for this PC entry
    uint64_t last_pa = StrLastPA[s_str];
    int64_t  delta   = int64_t(paddr) - int64_t(last_pa);
    int8_t   cur_d   = 0;
    if (delta >= LINE_SIZE && (delta % LINE_SIZE) == 0)
        cur_d = int8_t(delta / LINE_SIZE);
    // train counter
    if (cur_d != 0 && cur_d == StrLastDelta[s_str]) {
        if (StrCnt[s_str] < STR_MAX) StrCnt[s_str]++;
    } else {
        if (StrCnt[s_str] > 0) StrCnt[s_str]--;
    }
    StrLastPA[s_str]    = uint32_t(paddr);
    StrLastDelta[s_str] = cur_d;

    bool is_stream = (StrCnt[s_str] >= STR_THRES);

    // 2) Decide insertion RRPV
    if (is_stream) {
        // bypass streaming: deep insert
        RRPV[set][way] = MAX_RRPV;
    } else {
        // standard SHiP+SRRIP: hot PC => MRU, else SRRIP insertion
        if (SigTable[s_sig] >= SHIP_THRESHOLD) {
            RRPV[set][way] = 0;
        } else {
            RRPV[set][way] = MAX_RRPV - 1; // RRPV=2
        }
    }
}

void PrintStats() {
    // no extra stats
}

void PrintStats_Heartbeat() {
    // no-op
}