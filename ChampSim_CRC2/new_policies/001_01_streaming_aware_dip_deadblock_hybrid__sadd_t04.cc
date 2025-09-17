#include <vector>
#include <cstdint>
#include <cstring>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- Parameters ---
#define STREAM_DETECT_HISTORY 4
#define STREAM_DETECT_MATCH 3
#define STREAM_COUNTER_BITS 2 // per-set
#define DEAD_BLOCK_BITS 2     // per-line
#define DIP_PSEL_BITS 10
#define DIP_LEADER_SETS 32
#define DIP_BIP_PROB 32       // Insert at MRU 1/32 fills in BIP

// --- Replacement State ---
struct LineState {
    uint8_t dead : DEAD_BLOCK_BITS;
};

struct SetState {
    int64_t deltas[STREAM_DETECT_HISTORY];
    uint8_t ptr;
    uint8_t stream_ctr : STREAM_COUNTER_BITS;
    bool streaming;
};

std::vector<LineState> line_state; // LLC_SETS * LLC_WAYS
std::vector<SetState> set_state;   // LLC_SETS

// DIP set-dueling
uint16_t psel = (1 << (DIP_PSEL_BITS - 1)); // 10-bit PSEL
std::vector<uint8_t> is_leader; // LLC_SETS: 1=LIP leader, 2=BIP leader, 0=follower

std::vector<uint64_t> last_addr; // LLC_SETS

// --- Helper Functions ---
inline bool is_streaming_set(uint32_t set) {
    return set_state[set].streaming;
}

inline bool is_leader_set(uint32_t set) {
    if (set < DIP_LEADER_SETS) return 1; // LIP leader
    if (set >= LLC_SETS - DIP_LEADER_SETS) return 2; // BIP leader
    return 0;
}

// --- API Functions ---
void InitReplacementState() {
    line_state.resize(LLC_SETS * LLC_WAYS);
    set_state.resize(LLC_SETS);
    is_leader.resize(LLC_SETS, 0);
    last_addr.resize(LLC_SETS, 0);

    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        if (set < DIP_LEADER_SETS)
            is_leader[set] = 1; // LIP leader
        else if (set >= LLC_SETS - DIP_LEADER_SETS)
            is_leader[set] = 2; // BIP leader
        else
            is_leader[set] = 0; // follower

        set_state[set].ptr = 0;
        set_state[set].stream_ctr = 0;
        set_state[set].streaming = false;
        memset(set_state[set].deltas, 0, sizeof(set_state[set].deltas));
        last_addr[set] = 0;

        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            line_state[set * LLC_WAYS + way].dead = 0;
        }
    }
    psel = (1 << (DIP_PSEL_BITS - 1));
}

// Find victim in the set
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Streaming: bypass if detected (never insert)
    if (is_streaming_set(set)) {
        // Find dead block if possible
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (line_state[set * LLC_WAYS + way].dead == 3)
                return way;
        }
        // Otherwise, evict LRU (way 0)
        return 0;
    }
    // Normal: prefer dead blocks, then LRU
    for (uint32_t way = 0; way < LLC_WAYS; ++way) {
        if (line_state[set * LLC_WAYS + way].dead == 3)
            return way;
    }
    return 0; // LRU (way 0)
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
    // --- Streaming Detector ---
    int64_t delta = 0;
    if (last_addr[set]) delta = (int64_t)paddr - (int64_t)last_addr[set];
    last_addr[set] = paddr;
    SetState &ss = set_state[set];
    ss.deltas[ss.ptr] = delta;
    ss.ptr = (ss.ptr + 1) % STREAM_DETECT_HISTORY;
    // Detect monotonic pattern
    int match = 0;
    for (uint8_t i = 1; i < STREAM_DETECT_HISTORY; ++i) {
        if (ss.deltas[i] == ss.deltas[0] && ss.deltas[0] != 0)
            match++;
    }
    // Use a 2-bit saturating counter to smooth detection
    if (match >= STREAM_DETECT_MATCH) {
        if (ss.stream_ctr < 3) ss.stream_ctr++;
    } else {
        if (ss.stream_ctr > 0) ss.stream_ctr--;
    }
    ss.streaming = (ss.stream_ctr >= 2);

    // --- Dead-block counter decay (every 256 fills) ---
    static uint64_t fill_count = 0;
    fill_count++;
    if ((fill_count & 0xFF) == 0) {
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            for (uint32_t w = 0; w < LLC_WAYS; ++w)
                if (line_state[s * LLC_WAYS + w].dead)
                    line_state[s * LLC_WAYS + w].dead--;
    }

    // --- DIP: choose insertion policy ---
    uint8_t use_lip = 0;
    if (is_leader[set] == 1) use_lip = 1;
    else if (is_leader[set] == 2) use_lip = 0;
    else use_lip = (psel >= (1 << (DIP_PSEL_BITS - 1)));

    // --- On hit ---
    if (hit) {
        // Mark block as not dead
        if (line_state[set * LLC_WAYS + way].dead)
            line_state[set * LLC_WAYS + way].dead--;
        return;
    }

    // --- On fill ---
    if (ss.streaming) {
        // Streaming: bypass (never insert) and mark as dead
        line_state[set * LLC_WAYS + way].dead = 3;
        return;
    }

    // DIP insertion depth
    if (use_lip) {
        // LIP: always insert at LRU (way 0), mark as not dead
        line_state[set * LLC_WAYS + way].dead = 0;
    } else {
        // BIP: insert at MRU (way 15) 1/32 fills, else LRU
        static uint32_t bip_ctr = 0;
        bip_ctr = (bip_ctr + 1) % DIP_BIP_PROB;
        if (bip_ctr == 0)
            line_state[set * LLC_WAYS + way].dead = 0;
        else
            line_state[set * LLC_WAYS + way].dead = 1;
    }

    // --- On eviction: update dead-block ---
    if (victim_addr) {
        // If block was not reused, increment dead counter
        if (!hit) {
            if (line_state[set * LLC_WAYS + way].dead < 3)
                line_state[set * LLC_WAYS + way].dead++;
        }
    }

    // --- DIP set-dueling update ---
    if (is_leader[set] == 1 && !hit)
        psel = std::min((uint16_t)(psel + 1), (uint16_t)((1 << DIP_PSEL_BITS) - 1));
    else if (is_leader[set] == 2 && !hit)
        psel = (psel > 0) ? psel - 1 : 0;
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "SADD Policy: Streaming-aware DIP + Dead-block hybrid\n";
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // Optionally print periodic stats
}