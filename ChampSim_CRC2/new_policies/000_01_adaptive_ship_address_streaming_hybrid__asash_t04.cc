#include <vector>
#include <cstdint>
#include <cstring>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// RRIP constants
#define RRPV_BITS 2
#define MAX_RRPV ((1 << RRPV_BITS) - 1)
#define SHIP_SIG_BITS 6
#define SHIP_OUTCOME_BITS 2
#define SHIP_TABLE_SIZE (1 << SHIP_SIG_BITS)
#define STREAM_STRIDE_BITS 2
#define LEADER_SETS 64
#define PSEL_BITS 10
#define PSEL_MAX ((1 << PSEL_BITS) - 1)
#define PSEL_INIT (PSEL_MAX / 2)

// Replacement metadata
struct BlockMeta {
    uint8_t rrpv; // 2 bits
    uint8_t ship_sig; // 6 bits
    uint8_t ship_outcome; // 2 bits
};

std::vector<std::vector<BlockMeta>> block_meta(LLC_SETS, std::vector<BlockMeta>(LLC_WAYS));

// SHiP signature outcome table
struct SHIPEntry {
    uint8_t outcome; // 2 bits
};
std::vector<SHIPEntry> ship_table(SHIP_TABLE_SIZE);

// Streaming detector per set: stride direction (2 bits)
std::vector<uint8_t> stream_stride(LLC_SETS, 0);
// Last address per set for stride detection
std::vector<uint64_t> last_addr(LLC_SETS, 0);

// Set-dueling: leader sets for SRRIP and BRRIP
std::vector<uint8_t> is_leader(LLC_SETS, 0); // 0: normal, 1: SRRIP leader, 2: BRRIP leader
uint16_t psel = PSEL_INIT;

// Utility: get SHiP signature (lower 6 bits of PC)
inline uint8_t get_ship_sig(uint64_t PC) {
    return (PC >> 2) & (SHIP_TABLE_SIZE - 1);
}

// Utility: streaming detector update
inline bool detect_stream(uint32_t set, uint64_t addr) {
    uint64_t last = last_addr[set];
    bool stream = false;
    if (last) {
        int64_t delta = (int64_t)addr - (int64_t)last;
        if (delta == 64 || delta == -64) { // 64B line stride
            stream_stride[set] = std::min(stream_stride[set] + 1, (uint8_t)((1 << STREAM_STRIDE_BITS) - 1));
        } else {
            stream_stride[set] = 0;
        }
        if (stream_stride[set] >= 2) // threshold: 2 consecutive strides
            stream = true;
    }
    last_addr[set] = addr;
    return stream;
}

// Set-dueling assignment
void assign_leader_sets() {
    for (uint32_t i = 0; i < LLC_SETS; ++i) {
        if (i < LEADER_SETS)
            is_leader[i] = 1; // SRRIP leader
        else if (i >= LLC_SETS - LEADER_SETS)
            is_leader[i] = 2; // BRRIP leader
        else
            is_leader[i] = 0;
    }
}

// Initialize replacement state
void InitReplacementState() {
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            block_meta[set][way] = {MAX_RRPV, 0, 0};
    for (auto& entry : ship_table)
        entry.outcome = 1; // neutral
    assign_leader_sets();
    std::fill(stream_stride.begin(), stream_stride.end(), 0);
    std::fill(last_addr.begin(), last_addr.end(), 0);
    psel = PSEL_INIT;
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
    // Streaming detection
    bool is_stream = detect_stream(set, paddr);

    // Victim selection: standard RRIP
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (block_meta[set][way].rrpv == MAX_RRPV)
                return way;
        }
        // Increment RRPV of all blocks
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (block_meta[set][way].rrpv < MAX_RRPV)
                block_meta[set][way].rrpv++;
    }
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
    // Streaming detection
    bool is_stream = detect_stream(set, paddr);

    // SHiP signature
    uint8_t sig = get_ship_sig(PC);

    // On hit: promote block
    if (hit) {
        block_meta[set][way].rrpv = 0;
        // Update SHiP outcome counter
        if (block_meta[set][way].ship_outcome < ((1 << SHIP_OUTCOME_BITS) - 1))
            block_meta[set][way].ship_outcome++;
        if (ship_table[block_meta[set][way].ship_sig].outcome < ((1 << SHIP_OUTCOME_BITS) - 1))
            ship_table[block_meta[set][way].ship_sig].outcome++;
    } else {
        // On fill: set signature
        block_meta[set][way].ship_sig = sig;
        block_meta[set][way].ship_outcome = ship_table[sig].outcome;

        // Set-dueling: choose insertion policy
        uint8_t leader = is_leader[set];
        bool use_srrip = false;
        if (leader == 1)
            use_srrip = true;
        else if (leader == 2)
            use_srrip = false;
        else
            use_srrip = (psel >= (PSEL_MAX / 2));

        // SHiP outcome: if high reuse, protect
        bool high_reuse = (ship_table[sig].outcome >= ((1 << SHIP_OUTCOME_BITS) - 1));
        uint8_t insert_rrpv = MAX_RRPV;
        if (is_stream) {
            insert_rrpv = MAX_RRPV; // streaming: distant insertion
        } else if (high_reuse) {
            insert_rrpv = MAX_RRPV - 1; // protect
        } else if (use_srrip) {
            insert_rrpv = MAX_RRPV - 1; // SRRIP: insert at 2
        } else {
            insert_rrpv = MAX_RRPV; // BRRIP: insert at 3
        }
        block_meta[set][way].rrpv = insert_rrpv;
    }

    // Dead-block detection: on eviction, if no reuse, decay outcome
    if (!hit) {
        // Find victim block being evicted
        for (uint32_t w = 0; w < LLC_WAYS; ++w) {
            if (current_set[w].address == victim_addr) {
                uint8_t evict_sig = block_meta[set][w].ship_sig;
                if (block_meta[set][w].ship_outcome > 0)
                    block_meta[set][w].ship_outcome--;
                if (ship_table[evict_sig].outcome > 0)
                    ship_table[evict_sig].outcome--;
                break;
            }
        }
    }

    // Set-dueling: update PSEL
    uint8_t leader = is_leader[set];
    if (leader == 1) { // SRRIP leader
        if (hit && !is_stream && !high_reuse && type == 0) { // demand hit, not streaming
            if (psel < PSEL_MAX) psel++;
        }
    } else if (leader == 2) { // BRRIP leader
        if (hit && !is_stream && !high_reuse && type == 0) {
            if (psel > 0) psel--;
        }
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    std::cout << "ASASH Policy: End of simulation stats\n";
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // No-op
}