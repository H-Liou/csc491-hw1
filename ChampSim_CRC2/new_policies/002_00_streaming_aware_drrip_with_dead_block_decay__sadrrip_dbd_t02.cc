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
#define DEAD_BITS 2
#define STREAM_DELTA_HISTORY 4
#define STREAM_DELTA_THRESHOLD 3
#define PSEL_BITS 10
#define LEADER_SETS 32
#define DECAY_INTERVAL 4096 // lines

// --- Replacement State ---
struct LineState {
    uint8_t rrpv : RRPV_BITS;
    uint8_t dead : DEAD_BITS;
};

struct StreamHistory {
    int64_t deltas[STREAM_DELTA_HISTORY];
    uint8_t ptr;
    bool streaming;
};

std::vector<LineState> line_state; // LLC_SETS * LLC_WAYS
std::vector<StreamHistory> stream_hist; // LLC_SETS
std::vector<uint64_t> last_addr; // LLC_SETS
std::vector<uint8_t> is_leader_set; // LLC_SETS

uint16_t psel = 512; // 10-bit PSEL, midpoint
uint64_t fill_count = 0;

// --- Helper Functions ---
inline bool is_streaming_set(uint32_t set) {
    return stream_hist[set].streaming;
}

inline uint8_t get_leader_type(uint32_t set) {
    if (set < LEADER_SETS) return 1; // SRRIP leader
    if (set >= LLC_SETS - LEADER_SETS) return 2; // BRRIP leader
    return 0;
}

// --- API Functions ---
void InitReplacementState() {
    line_state.resize(LLC_SETS * LLC_WAYS);
    stream_hist.resize(LLC_SETS);
    last_addr.resize(LLC_SETS, 0);
    is_leader_set.resize(LLC_SETS, 0);

    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        if (set < LEADER_SETS)
            is_leader_set[set] = 1; // SRRIP leader
        else if (set >= LLC_SETS - LEADER_SETS)
            is_leader_set[set] = 2; // BRRIP leader
        else
            is_leader_set[set] = 0; // follower
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            line_state[set * LLC_WAYS + way].rrpv = RRPV_MAX;
            line_state[set * LLC_WAYS + way].dead = 0;
        }
        stream_hist[set].ptr = 0;
        stream_hist[set].streaming = false;
        memset(stream_hist[set].deltas, 0, sizeof(stream_hist[set].deltas));
    }
    psel = 512;
    fill_count = 0;
}

uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Streaming: do not bypass, but prefer dead blocks
    uint32_t victim = LLC_WAYS;
    // First, try dead blocks with RRPV==RRPV_MAX
    for (uint32_t way = 0; way < LLC_WAYS; ++way) {
        LineState &ls = line_state[set * LLC_WAYS + way];
        if (ls.rrpv == RRPV_MAX && ls.dead == (DEAD_BITS == 2 ? 3 : 1)) {
            victim = way;
            break;
        }
    }
    // If none, use standard RRIP victim selection
    if (victim == LLC_WAYS) {
        while (true) {
            for (uint32_t way = 0; way < LLC_WAYS; ++way) {
                if (line_state[set * LLC_WAYS + way].rrpv == RRPV_MAX) {
                    victim = way;
                    break;
                }
            }
            if (victim != LLC_WAYS)
                break;
            // Increment all RRPVs
            for (uint32_t way = 0; way < LLC_WAYS; ++way)
                if (line_state[set * LLC_WAYS + way].rrpv < RRPV_MAX)
                    line_state[set * LLC_WAYS + way].rrpv++;
        }
    }
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

    // --- Dead-block decay ---
    fill_count++;
    if (fill_count % DECAY_INTERVAL == 0) {
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            for (uint32_t w = 0; w < LLC_WAYS; ++w)
                if (line_state[s * LLC_WAYS + w].dead > 0)
                    line_state[s * LLC_WAYS + w].dead--;
    }

    // --- On hit ---
    if (hit) {
        // Reset RRPV to 0 (MRU)
        line_state[set * LLC_WAYS + way].rrpv = 0;
        // Mark as not dead
        line_state[set * LLC_WAYS + way].dead = 0;
        return;
    }

    // --- On fill ---
    uint8_t insert_rrpv = RRPV_MAX - 1; // default SRRIP

    // Streaming: insert at distant RRPV (max)
    if (sh.streaming) {
        insert_rrpv = RRPV_MAX;
    } else {
        // Dead-block: if victim was dead, insert at max RRPV
        if (line_state[set * LLC_WAYS + way].dead == (DEAD_BITS == 2 ? 3 : 1))
            insert_rrpv = RRPV_MAX;
        else {
            // DRRIP set-dueling
            uint8_t use_srrip = 0;
            if (is_leader_set[set] == 1) use_srrip = 1;
            else if (is_leader_set[set] == 2) use_srrip = 0;
            else use_srrip = (psel >= 512);

            if (use_srrip)
                insert_rrpv = RRPV_MAX - 1; // SRRIP: 1
            else
                insert_rrpv = (rand() % 32 == 0) ? RRPV_MAX - 1 : RRPV_MAX; // BRRIP: 1/32 at 1, else at max
        }
    }
    line_state[set * LLC_WAYS + way].rrpv = insert_rrpv;
    line_state[set * LLC_WAYS + way].dead = 0; // new block is not dead

    // --- On eviction: update dead-block counter ---
    if (victim_addr) {
        // If evicted block was not reused (RRPV==max), increment dead counter
        if (line_state[set * LLC_WAYS + way].rrpv == RRPV_MAX &&
            line_state[set * LLC_WAYS + way].dead < (DEAD_BITS == 2 ? 3 : 1))
            line_state[set * LLC_WAYS + way].dead++;
    }

    // --- DRRIP set-dueling update ---
    if (is_leader_set[set] == 1 && !hit)
        psel = std::min((uint16_t)(psel + 1), (uint16_t)((1 << PSEL_BITS) - 1));
    else if (is_leader_set[set] == 2 && !hit)
        psel = (psel > 0) ? psel - 1 : 0;
}

void PrintStats() {
    std::cout << "SADRRIP-DBD Policy: Streaming-aware DRRIP + dead-block decay\n";
}

void PrintStats_Heartbeat() {
    // Optionally print periodic stats
}