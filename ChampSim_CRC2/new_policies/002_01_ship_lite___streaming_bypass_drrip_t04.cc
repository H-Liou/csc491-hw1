#include <vector>
#include <cstdint>
#include <cstring>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// ---- Metadata Structures ----

// DRRIP set-dueling
constexpr uint32_t PSEL_BITS = 10;
uint16_t PSEL = 1 << (PSEL_BITS - 1); // 10-bit selector
constexpr uint32_t NUM_LEADER_SETS = 32;
std::vector<bool> is_srrip_leader(LLC_SETS, false);
std::vector<bool> is_brrip_leader(LLC_SETS, false);

// Per-line RRPV (2 bits)
std::vector<std::vector<uint8_t>> RRPV(LLC_SETS, std::vector<uint8_t>(LLC_WAYS, 3));

// SHiP-lite: 4-bit PC signature, 2-bit outcome counter
constexpr uint32_t SHIP_SIG_BITS = 4;
constexpr uint32_t SHIP_TABLE_SIZE = 2048;
struct SHIPEntry {
    uint8_t outcome : 2; // 2-bit counter
    uint16_t signature : SHIP_SIG_BITS;
};
std::vector<SHIPEntry> SHIP_table(SHIP_TABLE_SIZE);

// Per-line SHiP signature
std::vector<std::vector<uint16_t>> LINE_SIG(LLC_SETS, std::vector<uint16_t>(LLC_WAYS, 0));

// Streaming detector: per-set last address, last delta, streaming counter
struct StreamDetect {
    uint64_t last_addr;
    int64_t last_delta;
    uint8_t stream_count;
};
std::vector<StreamDetect> STREAM_DETECT(LLC_SETS);

// ---- Helper Functions ----

// Hash PC to SHiP signature
inline uint16_t SHIP_get_sig(uint64_t PC) {
    return (PC ^ (PC >> 4) ^ (PC >> 8)) & ((1 << SHIP_SIG_BITS) - 1);
}

// Index into SHIP table
inline uint32_t SHIP_index(uint16_t sig) {
    return sig;
}

// ---- Initialization ----
void InitReplacementState() {
    // Set up leader sets for SRRIP/BRRIP
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i) {
        is_srrip_leader[i] = true;
        is_brrip_leader[LLC_SETS - 1 - i] = true;
    }
    // Clear SHIP table
    for (auto& entry : SHIP_table) {
        entry.outcome = 1; // neutral
        entry.signature = 0;
    }
    // Clear streaming detector
    for (auto& sd : STREAM_DETECT) {
        sd.last_addr = 0;
        sd.last_delta = 0;
        sd.stream_count = 0;
    }
    // Set all RRPV to max (3)
    for (auto& set : RRPV)
        std::fill(set.begin(), set.end(), 3);
}

// ---- Victim Selection ----
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Streaming detection: if streaming, insert at distant RRPV
    bool streaming = false;
    int64_t cur_delta = 0;
    if (STREAM_DETECT[set].last_addr) {
        cur_delta = (int64_t)paddr - (int64_t)STREAM_DETECT[set].last_addr;
        if (cur_delta == STREAM_DETECT[set].last_delta && cur_delta != 0) {
            if (STREAM_DETECT[set].stream_count >= 4)
                streaming = true;
        }
    }

    // Find victim: standard SRRIP
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (RRPV[set][way] == 3)
                return way;
        }
        // Increment RRPVs
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (RRPV[set][way] < 3)
                ++RRPV[set][way];
    }
}

// ---- Update Replacement State ----
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
    // --- Streaming detector update ---
    int64_t cur_delta = 0;
    if (STREAM_DETECT[set].last_addr) {
        cur_delta = (int64_t)paddr - (int64_t)STREAM_DETECT[set].last_addr;
        if (cur_delta == STREAM_DETECT[set].last_delta && cur_delta != 0) {
            if (STREAM_DETECT[set].stream_count < 15)
                STREAM_DETECT[set].stream_count++;
        } else {
            STREAM_DETECT[set].stream_count = 0;
        }
        STREAM_DETECT[set].last_delta = cur_delta;
    }
    STREAM_DETECT[set].last_addr = paddr;

    // --- SHiP signature ---
    uint16_t sig = SHIP_get_sig(PC);
    uint32_t idx = SHIP_index(sig);

    // On hit: update SHiP outcome
    if (hit) {
        if (SHIP_table[idx].outcome < 3)
            SHIP_table[idx].outcome++;
    } else {
        if (SHIP_table[idx].outcome > 0)
            SHIP_table[idx].outcome--;
    }

    // --- Insertion policy ---
    bool streaming = (STREAM_DETECT[set].stream_count >= 4);
    uint8_t insert_rrpv = 2; // Default SRRIP

    // Set-dueling: choose SRRIP/BRRIP for leader sets
    bool use_brrip = false;
    if (is_srrip_leader[set])
        use_brrip = false;
    else if (is_brrip_leader[set])
        use_brrip = true;
    else
        use_brrip = (PSEL < (1 << (PSEL_BITS - 1)));

    // BRRIP: insert at RRPV=3 with low probability
    if (use_brrip) {
        insert_rrpv = (rand() % 32 == 0) ? 2 : 3;
    }

    // SHiP bias: if outcome counter is high, insert at RRPV=0
    if (SHIP_table[idx].outcome >= 2)
        insert_rrpv = 0;

    // Streaming: force distant RRPV
    if (streaming)
        insert_rrpv = 3;

    // Insert new line: set RRPV and signature
    RRPV[set][way] = insert_rrpv;
    LINE_SIG[set][way] = sig;

    // Update PSEL for leader sets
    if (is_srrip_leader[set]) {
        if (hit && PSEL < ((1 << PSEL_BITS) - 1)) PSEL++;
        else if (!hit && PSEL > 0) PSEL--;
    } else if (is_brrip_leader[set]) {
        if (hit && PSEL > 0) PSEL--;
        else if (!hit && PSEL < ((1 << PSEL_BITS) - 1)) PSEL++;
    }
}

// ---- Statistics ----
void PrintStats() {
    std::cout << "SHiP-Lite + Streaming Bypass DRRIP stats\n";
    std::cout << "PSEL final value: " << PSEL << std::endl;
}
void PrintStats_Heartbeat() {
    // Optional: print periodic SHIP table stats
}