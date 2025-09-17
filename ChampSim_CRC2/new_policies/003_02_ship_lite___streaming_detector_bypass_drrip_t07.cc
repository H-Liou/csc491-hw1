#include <vector>
#include <cstdint>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// RRIP definitions
#define MAX_RRPV 3 // 2 bits per line

// DRRIP PSEL and set-dueling
#define PSEL_BITS 10
#define PSEL_MAX ((1 << PSEL_BITS) - 1)
#define SD_LEADER_SETS 32 // 16 SRRIP, 16 BRRIP

// SHiP-lite definitions
#define SHIP_ENTRIES 8192 // 8K entries
#define SHIP_CTR_MAX 3    // 2 bits per entry
#define SIGNATURE_BITS 6  // 6 bits per entry

// Streaming detector definitions
#define STREAM_HIST_LEN 16 // address history per set
#define STREAM_DETECT_THRESH 12 // #monotonic deltas to trigger streaming
#define STREAM_STATE_BITS 2 // 2 bits per set

// Per-line replacement metadata
struct LINE_REPL_META {
    uint8_t rrpv;         // 2 bits
    uint16_t signature;   // 6 bits
    uint8_t outcome;      // 2 bits (SHiP)
};

std::vector<LINE_REPL_META> repl_meta(LLC_SETS * LLC_WAYS);

// SHiP-lite table
uint8_t SHIP_table[SHIP_ENTRIES]; // 2-bit outcome

// DRRIP PSEL
uint16_t PSEL = PSEL_MAX / 2;

// SRRIP/BRRIP leader sets
std::vector<uint8_t> is_srrip_leader(LLC_SETS, 0);
std::vector<uint8_t> is_brrip_leader(LLC_SETS, 0);

// Streaming detector state
struct STREAM_DETECT {
    uint64_t addr_hist[STREAM_HIST_LEN];
    uint8_t head;
    uint8_t monotonic_cnt;
    uint8_t stream_state; // 2 bits: 0=not streaming, 1=streaming, 2=recently streaming
};

std::vector<STREAM_DETECT> stream_meta(LLC_SETS);

inline uint16_t get_signature(uint64_t PC) {
    return (PC ^ (PC >> 16)) & (SHIP_ENTRIES - 1);
}

void InitReplacementState() {
    for (uint32_t s = 0; s < LLC_SETS; ++s) {
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            uint32_t idx = s * LLC_WAYS + w;
            repl_meta[idx].rrpv = MAX_RRPV;
            repl_meta[idx].signature = 0;
            repl_meta[idx].outcome = 1;
        }
        stream_meta[s].head = 0;
        stream_meta[s].monotonic_cnt = 0;
        stream_meta[s].stream_state = 0;
        for (uint8_t i = 0; i < STREAM_HIST_LEN; ++i)
            stream_meta[s].addr_hist[i] = 0;
    }
    memset(SHIP_table, 1, sizeof(SHIP_table)); // Neutral outcome
    PSEL = PSEL_MAX / 2;

    // Set leader sets for DRRIP set-dueling
    for (uint32_t i = 0; i < SD_LEADER_SETS; ++i) {
        is_srrip_leader[i] = 1;
        is_brrip_leader[LLC_SETS - 1 - i] = 1;
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
    // RRIP victim selection
    uint32_t base = set * LLC_WAYS;
    while (true) {
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            if (repl_meta[base + w].rrpv == MAX_RRPV) {
                return w;
            }
        }
        // Increment RRPV (aging)
        for (uint32_t w = 0; w < LLC_WAYS; ++w)
            if (repl_meta[base + w].rrpv < MAX_RRPV)
                repl_meta[base + w].rrpv++;
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
    uint32_t idx = set * LLC_WAYS + way;
    // --- SHiP-lite signature extraction ---
    uint16_t signature = get_signature(PC);

    // --- Streaming detector update ---
    STREAM_DETECT &sd = stream_meta[set];
    uint64_t prev_addr = sd.addr_hist[sd.head];
    sd.addr_hist[sd.head] = paddr >> 6; // block address
    sd.head = (sd.head + 1) % STREAM_HIST_LEN;

    // Check monotonic delta
    if (sd.head > 0) {
        uint64_t last = sd.addr_hist[(sd.head + STREAM_HIST_LEN - 1) % STREAM_HIST_LEN];
        uint64_t before_last = sd.addr_hist[(sd.head + STREAM_HIST_LEN - 2) % STREAM_HIST_LEN];
        int64_t delta = last - before_last;
        if (delta == 1 || delta == -1)
            sd.monotonic_cnt++;
        else if (sd.monotonic_cnt > 0)
            sd.monotonic_cnt--;
    }
    // Streaming state update
    if (sd.monotonic_cnt >= STREAM_DETECT_THRESH)
        sd.stream_state = 1;
    else if (sd.stream_state == 1 && sd.monotonic_cnt < STREAM_DETECT_THRESH / 2)
        sd.stream_state = 2; // recently streaming
    else if (sd.stream_state == 2 && sd.monotonic_cnt < STREAM_DETECT_THRESH / 4)
        sd.stream_state = 0;

    // On cache hit
    if (hit) {
        // SHiP outcome update
        if (SHIP_table[signature] < SHIP_CTR_MAX)
            SHIP_table[signature]++;
        repl_meta[idx].rrpv = 0; // Promote on hit
        repl_meta[idx].outcome = 1;
    } else {
        // Streaming bypass logic
        bool do_bypass = false;
        if (sd.stream_state == 1) {
            // Streaming: bypass with probability 7/8, else insert at RRPV=MAX
            if ((rand() & 7) != 0) do_bypass = true;
        }

        if (do_bypass) {
            // Don't insert; early eviction by marking RRPV=MAX
            repl_meta[idx].rrpv = MAX_RRPV;
            repl_meta[idx].signature = signature;
            repl_meta[idx].outcome = 0;
            return;
        }

        // DRRIP insertion policy selection
        bool srrip_mode = false, brrip_mode = false;
        if (is_srrip_leader[set]) srrip_mode = true;
        if (is_brrip_leader[set]) brrip_mode = true;
        if (!srrip_mode && !brrip_mode)
            srrip_mode = (PSEL >= (PSEL_MAX / 2));

        // SHiP insertion depth
        uint8_t insert_rrpv = MAX_RRPV;
        if (SHIP_table[signature] >= 2) {
            insert_rrpv = 0; // likely reusable
        } else if (SHIP_table[signature] == 1) {
            insert_rrpv = 2; // moderate
        } else {
            insert_rrpv = MAX_RRPV; // dead-on-arrival
        }

        // Apply DRRIP mode
        if (srrip_mode) {
            // SRRIP: insert at 2 (long term), unless SHiP says otherwise
            if (insert_rrpv > 2) insert_rrpv = 2;
        } else if (brrip_mode) {
            // BRRIP: insert at 3 (short term) ~1/32 times, otherwise at 2
            if (rand() % 32 == 0) insert_rrpv = MAX_RRPV;
            else if (insert_rrpv > 2) insert_rrpv = 2;
        }

        repl_meta[idx].rrpv = insert_rrpv;
        repl_meta[idx].signature = signature;
        repl_meta[idx].outcome = 0;
    }

    // PSEL update: only on leader sets
    if (is_srrip_leader[set]) {
        if (hit && type == 0 && PSEL < PSEL_MAX) PSEL++;
    }
    if (is_brrip_leader[set]) {
        if (hit && type == 0 && PSEL > 0) PSEL--;
    }
}

void PrintStats() {
    std::cout << "SHiP-Lite + Streaming Detector Bypass DRRIP stats\n";
}

void PrintStats_Heartbeat() {
    // No-op
}