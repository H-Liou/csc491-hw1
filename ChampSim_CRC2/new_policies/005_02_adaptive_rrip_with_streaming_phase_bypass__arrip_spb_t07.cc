#include <vector>
#include <cstdint>
#include <cstring>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- Parameters ---
#define RRPV_BITS 2
#define RRPV_MAX ((1 << RRPV_BITS) - 1)
#define REUSE_BITS 2
#define REUSE_MAX ((1 << REUSE_BITS) - 1)
#define STREAM_DELTA_HISTORY 4
#define STREAM_DELTA_THRESHOLD 3
#define SIG_BITS 4
#define SIG_TABLE_SIZE (1 << SIG_BITS) // 16
#define SIG_ENTRIES 1024 // 1K entries, 4 bits each

// --- Replacement State ---
struct LineState {
    uint8_t rrpv : RRPV_BITS;
    uint8_t reuse : REUSE_BITS;
    uint8_t signature : SIG_BITS;
};

struct StreamHistory {
    int64_t deltas[STREAM_DELTA_HISTORY];
    uint8_t ptr;
    bool streaming;
};

std::vector<LineState> line_state; // LLC_SETS * LLC_WAYS
std::vector<StreamHistory> stream_hist; // LLC_SETS
std::vector<uint64_t> last_addr; // LLC_SETS

// PC signature table: 1K entries, 4 bits each
std::vector<uint8_t> sig_table; // SIG_ENTRIES

// --- Helper Functions ---
inline uint16_t get_signature(uint64_t PC) {
    // Use lower SIG_BITS bits and simple fold
    return ((PC >> 2) ^ (PC >> 8)) & (SIG_ENTRIES - 1);
}

inline bool is_streaming_set(uint32_t set) {
    return stream_hist[set].streaming;
}

// --- API Functions ---
void InitReplacementState() {
    line_state.resize(LLC_SETS * LLC_WAYS);
    stream_hist.resize(LLC_SETS);
    last_addr.resize(LLC_SETS, 0);
    sig_table.resize(SIG_ENTRIES, 8); // Midpoint

    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            line_state[set * LLC_WAYS + way].rrpv = RRPV_MAX;
            line_state[set * LLC_WAYS + way].reuse = 0;
            line_state[set * LLC_WAYS + way].signature = 0;
        }
        stream_hist[set].ptr = 0;
        stream_hist[set].streaming = false;
        memset(stream_hist[set].deltas, 0, sizeof(stream_hist[set].deltas));
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
    // Streaming phase: bypass blocks with no reuse
    if (is_streaming_set(set)) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (line_state[set * LLC_WAYS + way].reuse == 0)
                return way;
        }
        // If none, fall back to RRIP
    }

    // RRIP victim selection: choose block with RRPV==max
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (line_state[set * LLC_WAYS + way].rrpv == RRPV_MAX)
                return way;
        }
        // Increment all RRPVs
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (line_state[set * LLC_WAYS + way].rrpv < RRPV_MAX)
                line_state[set * LLC_WAYS + way].rrpv++;
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
    // --- Streaming Detector ---
    int64_t delta = 0;
    if (last_addr[set]) delta = (int64_t)paddr - (int64_t)last_addr[set];
    last_addr[set] = paddr;
    StreamHistory &sh = stream_hist[set];
    sh.deltas[sh.ptr] = delta;
    sh.ptr = (sh.ptr + 1) % STREAM_DELTA_HISTORY;
    int match = 0;
    for (uint8_t i = 1; i < STREAM_DELTA_HISTORY; ++i) {
        if (sh.deltas[i] == sh.deltas[0] && sh.deltas[0] != 0)
            match++;
    }
    sh.streaming = (match >= STREAM_DELTA_THRESHOLD);

    // --- PC signature ---
    uint16_t sig = get_signature(PC);

    // --- Reuse counter update ---
    if (hit) {
        // Reuse detected
        line_state[set * LLC_WAYS + way].rrpv = 0;
        if (line_state[set * LLC_WAYS + way].reuse < REUSE_MAX)
            line_state[set * LLC_WAYS + way].reuse++;
        // Signature table: increment if not max
        if (sig_table[sig] < 15) sig_table[sig]++;
        return;
    } else {
        // Miss: decay reuse
        if (line_state[set * LLC_WAYS + way].reuse > 0)
            line_state[set * LLC_WAYS + way].reuse--;
    }

    // --- Streaming bypass ---
    if (sh.streaming && line_state[set * LLC_WAYS + way].reuse == 0) {
        // Do not fill cache (simulate bypass)
        return;
    }

    // --- Insertion depth logic ---
    uint8_t insert_rrpv = RRPV_MAX; // default: distant

    // If PC has shown reuse, insert at SRRIP-1
    if (sig_table[sig] >= 12)
        insert_rrpv = RRPV_MAX - 1; // likely reused
    else
        insert_rrpv = RRPV_MAX;     // likely dead

    // If streaming, always insert at max
    if (sh.streaming)
        insert_rrpv = RRPV_MAX;

    line_state[set * LLC_WAYS + way].rrpv = insert_rrpv;
    line_state[set * LLC_WAYS + way].signature = sig;
    line_state[set * LLC_WAYS + way].reuse = 0;

    // --- On eviction: decay signature table if block was dead
    if (victim_addr) {
        uint16_t victim_sig = line_state[set * LLC_WAYS + way].signature;
        if (line_state[set * LLC_WAYS + way].rrpv == RRPV_MAX && sig_table[victim_sig] > 0)
            sig_table[victim_sig]--;
    }
}

void PrintStats() {
    std::cout << "ARRIP-SPB Policy: Adaptive RRIP + streaming-phase bypass + lightweight PC reuse tracking\n";
}

void PrintStats_Heartbeat() {
    // Optionally print periodic stats
}