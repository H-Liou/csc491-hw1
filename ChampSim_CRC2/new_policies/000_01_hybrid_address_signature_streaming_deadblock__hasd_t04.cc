#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- Parameters ---
#define SIG_BITS 6          // 6-bit address signature
#define SIG_ENTRIES 64      // 2^6 signatures
#define SIG_REUSE_BITS 2    // 2-bit reuse counter per signature
#define DEAD_BITS 2         // 2-bit dead-block counter per line
#define STREAM_WIN 4        // Streaming window (delta history)
#define STREAM_THRESH 3     // Streaming threshold (monotonic deltas)
#define DIP_LEADER_SETS 64  // DIP leader sets
#define DIP_PSEL_BITS 10    // DIP PSEL counter bits

// --- Replacement State ---
struct LineState {
    uint8_t rrpv;           // 2-bit RRPV
    uint8_t dead;           // 2-bit dead-block counter
    uint8_t sig;            // 6-bit address signature
};

struct SetState {
    uint64_t delta_hist[STREAM_WIN]; // Last STREAM_WIN address deltas
    uint8_t delta_ptr;               // Pointer for circular buffer
    bool streaming;                  // Streaming detected
};

struct SigState {
    uint8_t reuse[SIG_ENTRIES];      // 2-bit reuse counter per signature
};

LineState repl_state[LLC_SETS][LLC_WAYS];
SetState set_state[LLC_SETS];
SigState sig_state[LLC_SETS];        // Per-set address signature table

// DIP: PSEL and leader sets
uint16_t dip_psel = (1 << (DIP_PSEL_BITS-1));
std::vector<uint32_t> dip_leader_lip;
std::vector<uint32_t> dip_leader_bip;

// Stats
uint64_t streaming_bypass = 0;
uint64_t dead_evictions = 0;

// Helper: Get address signature
inline uint8_t get_addr_sig(uint64_t paddr) {
    return (paddr >> 6) & ((1 << SIG_BITS) - 1); // block address bits [6:11]
}

// Helper: Is leader set
inline bool is_leader_lip(uint32_t set) {
    return std::find(dip_leader_lip.begin(), dip_leader_lip.end(), set) != dip_leader_lip.end();
}
inline bool is_leader_bip(uint32_t set) {
    return std::find(dip_leader_bip.begin(), dip_leader_bip.end(), set) != dip_leader_bip.end();
}

// --- Initialization ---
void InitReplacementState() {
    // Clear all replacement state
    memset(repl_state, 0, sizeof(repl_state));
    memset(set_state, 0, sizeof(set_state));
    memset(sig_state, 0, sizeof(sig_state));

    // Randomly assign DIP leader sets
    dip_leader_lip.clear();
    dip_leader_bip.clear();
    for (uint32_t i = 0; i < DIP_LEADER_SETS; ++i) {
        dip_leader_lip.push_back(i);
        dip_leader_bip.push_back(LLC_SETS/2 + i);
    }
}

// --- Streaming Detector ---
bool detect_streaming(uint32_t set, uint64_t paddr) {
    SetState &ss = set_state[set];
    uint64_t last_addr = ss.delta_hist[(ss.delta_ptr + STREAM_WIN - 1) % STREAM_WIN];
    uint64_t delta = (last_addr == 0) ? 0 : paddr - last_addr;
    ss.delta_hist[ss.delta_ptr] = paddr;
    ss.delta_ptr = (ss.delta_ptr + 1) % STREAM_WIN;

    // Check monotonic deltas
    int monotonic = 0;
    for (int i = 1; i < STREAM_WIN; ++i) {
        uint64_t d1 = ss.delta_hist[i] - ss.delta_hist[i-1];
        if (d1 == 64 || d1 == -64) monotonic++; // stride of 64 bytes
    }
    ss.streaming = (monotonic >= STREAM_THRESH);
    return ss.streaming;
}

// --- Find Victim ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Streaming bypass: if detected, do not fill (return -1)
    if (set_state[set].streaming)
        return LLC_WAYS; // special value: bypass

    // Dead-block priority: prefer blocks with dead=3, then max RRPV
    uint32_t victim = LLC_WAYS;
    for (uint32_t w = 0; w < LLC_WAYS; ++w) {
        if (repl_state[set][w].dead == 3) {
            victim = w;
            break;
        }
    }
    if (victim == LLC_WAYS) {
        // Find max RRPV
        uint8_t max_rrpv = 0;
        for (uint32_t w = 0; w < LLC_WAYS; ++w)
            if (repl_state[set][w].rrpv > max_rrpv)
                max_rrpv = repl_state[set][w].rrpv;
        for (uint32_t w = 0; w < LLC_WAYS; ++w)
            if (repl_state[set][w].rrpv == max_rrpv) {
                victim = w;
                break;
            }
    }
    // If still not found, pick way 0
    if (victim == LLC_WAYS)
        victim = 0;
    return victim;
}

// --- Update Replacement State ---
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
    // Streaming detection
    bool streaming = detect_streaming(set, paddr);

    // Get address signature
    uint8_t sig = get_addr_sig(paddr);

    // Dead-block decay: every 1024 fills, decay all dead counters in set
    static uint64_t fill_count = 0;
    fill_count++;
    if ((fill_count & 0x3FF) == 0) {
        for (uint32_t w = 0; w < LLC_WAYS; ++w)
            if (repl_state[set][w].dead > 0)
                repl_state[set][w].dead--;
    }

    // Streaming bypass: do not fill if streaming detected
    if (streaming) {
        streaming_bypass++;
        return;
    }

    // DIP insertion depth selection
    bool use_lip = false;
    if (is_leader_lip(set))
        use_lip = true;
    else if (is_leader_bip(set))
        use_lip = false;
    else
        use_lip = (dip_psel >= (1 << (DIP_PSEL_BITS-1)));

    // Signature reuse: if signature counter >=2, insert at MRU (rrpv=0)
    uint8_t sig_reuse = sig_state[set].reuse[sig];
    uint8_t new_rrpv = 3; // default: distant
    if (sig_reuse >= 2)
        new_rrpv = 0; // MRU
    else if (use_lip)
        new_rrpv = 3; // LIP: always distant
    else
        new_rrpv = (rand() % 32 == 0) ? 0 : 3; // BIP: MRU with low probability

    // Dead-block hint: if dead counter ==3, always distant
    if (repl_state[set][way].dead == 3)
        new_rrpv = 3;

    // Update line state
    repl_state[set][way].rrpv = new_rrpv;
    repl_state[set][way].dead = (hit) ? 0 : repl_state[set][way].dead + 1;
    if (repl_state[set][way].dead > 3) repl_state[set][way].dead = 3;
    repl_state[set][way].sig = sig;

    // Update signature reuse counter
    if (hit) {
        if (sig_state[set].reuse[sig] < 3)
            sig_state[set].reuse[sig]++;
    } else {
        if (sig_state[set].reuse[sig] > 0)
            sig_state[set].reuse[sig]--;
    }

    // DIP PSEL update for leader sets
    if (is_leader_lip(set) && hit)
        if (dip_psel < ((1 << DIP_PSEL_BITS)-1)) dip_psel++;
    if (is_leader_bip(set) && hit)
        if (dip_psel > 0) dip_psel--;

    // Dead-block eviction stats
    if (!hit && repl_state[set][way].dead == 3)
        dead_evictions++;
}

// --- Print Stats ---
void PrintStats() {
    std::cout << "HASD: Streaming bypasses = " << streaming_bypass << std::endl;
    std::cout << "HASD: Dead-block evictions = " << dead_evictions << std::endl;
}

void PrintStats_Heartbeat() {
    // Optionally print periodic stats
}