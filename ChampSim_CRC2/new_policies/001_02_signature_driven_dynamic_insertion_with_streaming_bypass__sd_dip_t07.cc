#include <vector>
#include <cstdint>
#include <cstring>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- Parameters ---
#define SHIP_SIG_BITS 6 // 64 entries per set
#define SHIP_SIG_ENTRIES (1 << SHIP_SIG_BITS)
#define SHIP_SIG_MASK (SHIP_SIG_ENTRIES - 1)
#define SHIP_SIG_COUNTER_BITS 2
#define RRPV_BITS 2
#define STREAM_DELTA_HISTORY 4 // per-set
#define STREAM_DELTA_THRESHOLD 3 // monotonic if >=3/4 deltas match
#define PSEL_BITS 10
#define LEADER_SETS 64 // 32 LIP, 32 BIP

// --- Replacement State ---
struct LineState {
    uint8_t rrpv : RRPV_BITS;
};

struct SHIPEntry {
    uint8_t counter : SHIP_SIG_COUNTER_BITS;
};

struct StreamHistory {
    int64_t deltas[STREAM_DELTA_HISTORY];
    uint8_t ptr;
    bool streaming;
};

std::vector<LineState> line_state; // LLC_SETS * LLC_WAYS
std::vector<SHIPEntry> ship_table; // LLC_SETS * SHIP_SIG_ENTRIES
std::vector<StreamHistory> stream_hist; // LLC_SETS
std::vector<uint64_t> last_addr; // LLC_SETS

// DIP set-dueling
std::vector<uint8_t> leader_type; // LLC_SETS: 0=normal, 1=LIP, 2=BIP
uint16_t psel = 512; // 10 bits, midpoint

inline uint32_t get_ship_sig(uint64_t PC) {
    return (PC >> 2) & SHIP_SIG_MASK;
}

// --- Initialization ---
void InitReplacementState() {
    line_state.resize(LLC_SETS * LLC_WAYS);
    ship_table.resize(LLC_SETS * SHIP_SIG_ENTRIES);
    stream_hist.resize(LLC_SETS);
    last_addr.resize(LLC_SETS, 0);
    leader_type.resize(LLC_SETS, 0);

    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        if (set < LEADER_SETS)
            leader_type[set] = 1; // LIP leader
        else if (set >= LLC_SETS - LEADER_SETS)
            leader_type[set] = 2; // BIP leader
        else
            leader_type[set] = 0; // follower

        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            line_state[set * LLC_WAYS + way].rrpv = 3; // distant

        for (uint32_t i = 0; i < SHIP_SIG_ENTRIES; ++i)
            ship_table[set * SHIP_SIG_ENTRIES + i].counter = 1;

        stream_hist[set].ptr = 0;
        stream_hist[set].streaming = false;
        memset(stream_hist[set].deltas, 0, sizeof(stream_hist[set].deltas));
    }
}

// --- Victim Selection ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Streaming: always evict block with max RRPV
    if (stream_hist[set].streaming) {
        uint32_t victim = 0;
        uint8_t max_rrpv = 0;
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            uint8_t rrpv = line_state[set * LLC_WAYS + way].rrpv;
            if (rrpv >= max_rrpv) {
                max_rrpv = rrpv;
                victim = way;
            }
        }
        return victim;
    }
    // Normal: evict block with max RRPV
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (line_state[set * LLC_WAYS + way].rrpv == 3)
                return way;
        }
        // Increment RRPV for all lines if no candidate
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            line_state[set * LLC_WAYS + way].rrpv = std::min(line_state[set * LLC_WAYS + way].rrpv + 1, (uint8_t)3);
    }
    return 0;
}

// --- Replacement State Update ---
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

    // --- SHiP signature ---
    uint32_t sig = get_ship_sig(PC);
    SHIPEntry &ship = ship_table[set * SHIP_SIG_ENTRIES + sig];

    // --- DIP Insertion Mode ---
    bool use_lip = false;
    if (leader_type[set] == 1) use_lip = true;
    else if (leader_type[set] == 2) use_lip = false;
    else use_lip = (psel >= 512);

    // --- On hit ---
    if (hit) {
        line_state[set * LLC_WAYS + way].rrpv = 0; // MRU
        ship.counter = std::min((uint8_t)(ship.counter + 1), (uint8_t)((1 << SHIP_SIG_COUNTER_BITS) - 1));
        return;
    }

    // --- On fill ---
    // Streaming: bypass fill (do not cache)
    if (sh.streaming) {
        line_state[set * LLC_WAYS + way].rrpv = 3; // insert as distant, expect eviction soon
        return;
    }

    // Strong SHiP reuse: insert at MRU
    if (ship.counter >= ((1 << SHIP_SIG_COUNTER_BITS) - 1)) {
        line_state[set * LLC_WAYS + way].rrpv = 0;
    }
    // Moderate SHiP reuse: insert at mid RRPV
    else if (ship.counter >= 2) {
        line_state[set * LLC_WAYS + way].rrpv = 1;
    }
    // Weak SHiP reuse: DIP logic
    else {
        // LIP: always distant (3)
        // BIP: MRU 1/32 fills, else distant
        if (use_lip) {
            line_state[set * LLC_WAYS + way].rrpv = 3;
        } else {
            static uint32_t bip_ctr = 0;
            if ((++bip_ctr & 0x1F) == 0)
                line_state[set * LLC_WAYS + way].rrpv = 0; // MRU
            else
                line_state[set * LLC_WAYS + way].rrpv = 3; // distant
        }
    }

    // --- On eviction: update SHiP ---
    if (victim_addr) {
        uint32_t victim_sig = get_ship_sig(PC);
        SHIPEntry &victim_ship = ship_table[set * SHIP_SIG_ENTRIES + victim_sig];
        if (!hit) {
            if (victim_ship.counter)
                victim_ship.counter--;
        }
    }

    // --- DIP set-dueling update ---
    if (leader_type[set] == 1 && !hit) { // LIP leader miss
        psel = (psel < ((1 << PSEL_BITS) - 1)) ? psel + 1 : psel;
    } else if (leader_type[set] == 2 && !hit) { // BIP leader miss
        psel = (psel > 0) ? psel - 1 : 0;
    }
}

// --- Statistics ---
void PrintStats() {
    std::cout << "SD-DIP Policy: SHiP-lite + DIP set-dueling + streaming bypass\n";
}

void PrintStats_Heartbeat() {
    // Optionally print periodic stats
}