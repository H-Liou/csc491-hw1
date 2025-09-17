#include <vector>
#include <cstdint>
#include <iostream>
#include <unordered_map>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// RRIP constants
#define MAX_RRPV 3
#define SHIP_SIG_BITS 6            // 6-bit PC signature
#define SHIP_CTR_BITS 2            // 2-bit saturating counter per signature
#define SHIP_SIG_ENTRIES 4096      // 4K signature entries
#define STREAM_WIN 4               // Streaming window size
#define STREAM_DELTA_THRESH 3      // Streaming delta threshold

// DRRIP set-dueling
#define NUM_LEADER_SETS 64
#define PSEL_MAX 1023
#define PSEL_MIN 0

// --- Metadata Structures ---

struct SHIPEntry {
    uint8_t ctr;   // 2-bit outcome counter
};

struct LineMeta {
    uint8_t rrpv;
    uint8_t outcome;
    uint16_t signature; // 6 bits
    uint8_t is_stream;
};

std::vector<std::vector<LineMeta>> line_meta(LLC_SETS, std::vector<LineMeta>(LLC_WAYS));
std::vector<SHIPEntry> ship_table(SHIP_SIG_ENTRIES);

// Streaming detector state per set
struct StreamDetector {
    uint64_t last_addr;
    int delta_cnt;
    int stream_dir; // +1, -1, or 0
};
std::vector<StreamDetector> stream_det(LLC_SETS);

// DRRIP set-dueling
std::vector<uint8_t> is_srrip_leader(LLC_SETS, 0);
std::vector<uint8_t> is_brrip_leader(LLC_SETS, 0);
int psel = PSEL_MAX / 2;

// Helper for SHIP signature
inline uint16_t get_signature(uint64_t PC) {
    return (PC ^ (PC >> 6) ^ (PC >> 12)) & ((1 << SHIP_SIG_BITS) - 1);
}

// Helper for DRRIP leader sets
inline bool is_leader(uint32_t set, bool srrip) {
    if (srrip) return is_srrip_leader[set];
    return is_brrip_leader[set];
}

// --- Initialization ---
void InitReplacementState() {
    // Mark leader sets
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i) {
        is_srrip_leader[i * (LLC_SETS / NUM_LEADER_SETS)] = 1;
        is_brrip_leader[i * (LLC_SETS / NUM_LEADER_SETS) + 1] = 1;
    }
    // Clear SHIP table
    for (auto& entry : ship_table) entry.ctr = 1;
    // Clear per-line metadata
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            line_meta[set][way] = {MAX_RRPV, 0, 0, 0};
        }
        stream_det[set] = {0, 0, 0};
    }
}

// --- Streaming Detector ---
// Returns true if streaming detected
bool detect_stream(uint32_t set, uint64_t addr) {
    auto& sd = stream_det[set];
    int64_t delta = addr - sd.last_addr;
    if (sd.last_addr == 0 || abs(delta) > (64 * LLC_WAYS)) {
        // Reset window if far jump
        sd.delta_cnt = 1;
        sd.stream_dir = (delta > 0) ? 1 : ((delta < 0) ? -1 : 0);
    } else if (delta == sd.stream_dir * 64) { // 64B block size stride
        if (sd.delta_cnt < STREAM_WIN) sd.delta_cnt++;
    } else {
        sd.delta_cnt = 1;
        sd.stream_dir = (delta > 0) ? 1 : ((delta < 0) ? -1 : 0);
    }
    sd.last_addr = addr;
    return (sd.delta_cnt >= STREAM_DELTA_THRESH);
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
    // Search for a block with MAX_RRPV
    for (uint32_t way = 0; way < LLC_WAYS; ++way) {
        if (line_meta[set][way].rrpv == MAX_RRPV)
            return way;
    }
    // If none, increment RRPVs and try again
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (line_meta[set][way].rrpv < MAX_RRPV)
                line_meta[set][way].rrpv++;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (line_meta[set][way].rrpv == MAX_RRPV)
                return way;
    }
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
    bool is_stream = detect_stream(set, paddr);

    // SHIP signature
    uint16_t sig = get_signature(PC);

    // On cache hit: promote block, mark reuse
    if (hit) {
        line_meta[set][way].rrpv = 0;
        line_meta[set][way].outcome = 1;
        line_meta[set][way].signature = sig;
        line_meta[set][way].is_stream = is_stream;
        // Train SHIP: increment outcome for this signature (max 3)
        if (ship_table[sig].ctr < 3) ship_table[sig].ctr++;
        return;
    }

    // On cache fill: determine insertion RRPV
    uint8_t ins_rrpv;
    if (is_stream) {
        ins_rrpv = MAX_RRPV; // Streaming: insert at distant, likely bypass
    } else if (ship_table[sig].ctr == 0) {
        ins_rrpv = MAX_RRPV; // No reuse seen for signature: distant insertion
    } else {
        // Use DRRIP set-dueling to pick SRRIP/BRRIP
        bool use_brrip = false;
        if (is_leader(set, true)) use_brrip = false;
        else if (is_leader(set, false)) use_brrip = true;
        else use_brrip = (psel < (PSEL_MAX / 2));
        ins_rrpv = use_brrip ? ((rand() % 32 == 0) ? MAX_RRPV-1 : MAX_RRPV) : MAX_RRPV-1;
    }

    // Insert block
    line_meta[set][way].rrpv = ins_rrpv;
    line_meta[set][way].outcome = 0;
    line_meta[set][way].signature = sig;
    line_meta[set][way].is_stream = is_stream;

    // Train SHIP: decrement outcome for victim's signature if not reused
    uint16_t victim_sig = line_meta[set][way].signature;
    if (!line_meta[set][way].outcome && ship_table[victim_sig].ctr > 0)
        ship_table[victim_sig].ctr--;

    // DRRIP set-dueling: update PSEL
    if (is_leader(set, true)) {
        if (hit) psel = std::min(psel+1, PSEL_MAX);
        else psel = std::max(psel-1, PSEL_MIN);
    } else if (is_leader(set, false)) {
        if (hit) psel = std::max(psel-1, PSEL_MIN);
        else psel = std::min(psel+1, PSEL_MAX);
    }
}

// --- Stats ---
void PrintStats() {
    // Optionally report SHIP counters or PSEL
    std::cout << "SDRRIP-S: Final PSEL=" << psel << std::endl;
}

void PrintStats_Heartbeat() {
    // Could print periodic streaming/bypass ratio
}