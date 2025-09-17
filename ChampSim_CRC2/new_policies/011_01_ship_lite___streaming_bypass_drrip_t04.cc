#include <vector>
#include <cstdint>
#include <iostream>
#include <algorithm>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// SHiP-lite parameters
#define SHIP_SIG_BITS 6
#define SHIP_SIG_MASK ((1<<SHIP_SIG_BITS)-1)
#define SHIP_ENTRIES (1<<SHIP_SIG_BITS)
#define SHIP_CNTR_BITS 2
#define SHIP_CNTR_MAX ((1<<SHIP_CNTR_BITS)-1)
#define SHIP_CNTR_INIT 1

// Streaming detector parameters
#define STREAM_CNTR_BITS 2
#define STREAM_CNTR_MAX ((1<<STREAM_CNTR_BITS)-1)
#define STREAM_DETECT_THRESH STREAM_CNTR_MAX

// DRRIP parameters
#define RRPV_BITS 2
#define RRPV_MAX ((1<<RRPV_BITS)-1)
#define SRRIP_INSERT 0
#define BRRIP_INSERT (RRPV_MAX-1)

// DRRIP set-dueling
#define PSEL_BITS 10
#define PSEL_MAX ((1<<PSEL_BITS)-1)
#define NUM_LEADER_SETS 32
#define LEADER_SET_STRIDE (LLC_SETS/NUM_LEADER_SETS)

struct block_state_t {
    uint8_t rrpv;          // 2 bits: RRIP value
    uint8_t ship_sig;      // 6 bits: PC signature
};

std::vector<std::vector<block_state_t>> blocks(LLC_SETS, std::vector<block_state_t>(LLC_WAYS));

// SHiP-lite outcome table: indexed by PC signature
struct ship_entry_t {
    uint8_t cntr; // 2 bits: reuse outcome counter
};
std::vector<ship_entry_t> ship_table(SHIP_ENTRIES);

// Streaming detector per set
struct stream_state_t {
    uint64_t last_addr;
    uint8_t stream_cntr; // 2 bits
};
std::vector<stream_state_t> stream_table(LLC_SETS);

// DRRIP set-dueling
std::vector<uint8_t> is_srrip_leader(LLC_SETS, 0);
std::vector<uint8_t> is_brrip_leader(LLC_SETS, 0);
uint16_t psel = PSEL_MAX/2;

// Utility: assign leader sets for SRRIP and BRRIP
void assign_leader_sets() {
    for(uint32_t i=0; i<NUM_LEADER_SETS; i++) {
        uint32_t srrip_set = i * LEADER_SET_STRIDE;
        uint32_t brrip_set = srrip_set + LEADER_SET_STRIDE/2;
        if(srrip_set < LLC_SETS)
            is_srrip_leader[srrip_set] = 1;
        if(brrip_set < LLC_SETS)
            is_brrip_leader[brrip_set] = 1;
    }
}

// PC signature hash (simple xor, mask)
inline uint8_t get_ship_sig(uint64_t PC) {
    return (uint8_t)((PC ^ (PC>>SHIP_SIG_BITS)) & SHIP_SIG_MASK);
}

// Streaming detector update
void update_stream_detector(uint32_t set, uint64_t paddr) {
    uint64_t last = stream_table[set].last_addr;
    if(last != 0) {
        int64_t delta = (int64_t)paddr - (int64_t)last;
        // Detect monotonic stride (forward/backward)
        if(delta == 64 || delta == -64) { // 64B line stride
            if(stream_table[set].stream_cntr < STREAM_CNTR_MAX)
                stream_table[set].stream_cntr++;
        } else {
            if(stream_table[set].stream_cntr > 0)
                stream_table[set].stream_cntr--;
        }
    }
    stream_table[set].last_addr = paddr;
}

// Initialize replacement state
void InitReplacementState() {
    for(uint32_t s=0; s<LLC_SETS; s++) {
        for(uint32_t w=0; w<LLC_WAYS; w++) {
            blocks[s][w] = {RRPV_MAX, 0}; // RRPV, ship_sig
        }
        stream_table[s] = {0, 0};
    }
    for(uint32_t i=0; i<SHIP_ENTRIES; i++)
        ship_table[i] = {SHIP_CNTR_INIT};
    assign_leader_sets();
    psel = PSEL_MAX/2;
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
    // Standard RRIP victim selection
    while(true) {
        for(uint32_t w=0; w<LLC_WAYS; w++)
            if(blocks[set][w].rrpv == RRPV_MAX)
                return w;
        for(uint32_t w=0; w<LLC_WAYS; w++)
            if(blocks[set][w].rrpv < RRPV_MAX)
                blocks[set][w].rrpv++;
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
    // Update streaming detector
    update_stream_detector(set, paddr);

    // Get PC signature
    uint8_t ship_sig = get_ship_sig(PC);

    // On hit: set block to MRU, increment SHiP outcome counter
    if(hit) {
        blocks[set][way].rrpv = SRRIP_INSERT;
        blocks[set][way].ship_sig = ship_sig;
        if(ship_table[ship_sig].cntr < SHIP_CNTR_MAX)
            ship_table[ship_sig].cntr++;
        // Update PSEL for leader sets
        if(is_srrip_leader[set] && psel < PSEL_MAX)
            psel++;
        if(is_brrip_leader[set] && psel > 0)
            psel--;
        return;
    }

    // On fill/replace: decrement SHiP outcome counter for victim block
    uint8_t victim_sig = blocks[set][way].ship_sig;
    if(ship_table[victim_sig].cntr > 0)
        ship_table[victim_sig].cntr--;

    // Streaming bypass: if streaming detected, insert at distant RRPV
    bool streaming = (stream_table[set].stream_cntr >= STREAM_DETECT_THRESH);

    // Decide insertion RRPV
    uint8_t ins_rrpv;
    if(streaming) {
        ins_rrpv = RRPV_MAX; // streaming: insert at distant RRPV (effectively bypass)
    } else if(is_srrip_leader[set]) {
        ins_rrpv = SRRIP_INSERT;
    } else if(is_brrip_leader[set]) {
        ins_rrpv = BRRIP_INSERT;
    } else {
        // SHiP bias: high outcome counter → SRRIP, low → BRRIP
        ins_rrpv = (ship_table[ship_sig].cntr >= (SHIP_CNTR_MAX/2)) ? SRRIP_INSERT : BRRIP_INSERT;
        // DRRIP fallback: if PSEL is high, prefer SRRIP
        if(psel >= PSEL_MAX/2)
            ins_rrpv = SRRIP_INSERT;
    }

    blocks[set][way].rrpv = ins_rrpv;
    blocks[set][way].ship_sig = ship_sig;
}

// Print end-of-simulation statistics
void PrintStats() {
    int streaming_sets = 0;
    for(uint32_t s=0; s<LLC_SETS; s++) {
        if(stream_table[s].stream_cntr >= STREAM_DETECT_THRESH)
            streaming_sets++;
    }
    int ship_high = 0;
    for(uint32_t i=0; i<SHIP_ENTRIES; i++)
        if(ship_table[i].cntr >= SHIP_CNTR_MAX/2)
            ship_high++;
    std::cout << "SHiP-Lite+Streaming: Streaming sets = " << streaming_sets << "/" << LLC_SETS << std::endl;
    std::cout << "SHiP-Lite+Streaming: SHiP high-reuse sigs = " << ship_high << "/" << SHIP_ENTRIES << std::endl;
    std::cout << "SHiP-Lite+Streaming: PSEL = " << psel << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // No periodic stats needed
}