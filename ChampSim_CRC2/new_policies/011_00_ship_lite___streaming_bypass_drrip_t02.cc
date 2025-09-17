#include <vector>
#include <cstdint>
#include <iostream>
#include <algorithm>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// RRIP parameters
#define RRPV_BITS 2
#define RRPV_MAX ((1<<RRPV_BITS)-1)
#define SRRIP_INSERT 0
#define BRRIP_INSERT (RRPV_MAX-1)

// DRRIP set-dueling
#define PSEL_BITS 10
#define PSEL_MAX ((1<<PSEL_BITS)-1)
#define NUM_LEADER_SETS 32
#define LEADER_SET_STRIDE (LLC_SETS/NUM_LEADER_SETS)

// SHiP-lite parameters
#define SHIP_SIG_BITS 6
#define SHIP_SIG_ENTRIES 2048
#define SHIP_SIG_MASK (SHIP_SIG_ENTRIES-1)
#define SHIP_COUNTER_BITS 2
#define SHIP_COUNTER_MAX ((1<<SHIP_COUNTER_BITS)-1)
#define SHIP_COUNTER_INIT 1

// Streaming detector parameters
#define STREAM_WINDOW 4
#define STREAM_DELTA_THRESHOLD 3

struct block_state_t {
    uint8_t rrpv;      // 2 bits: RRIP value
    uint16_t signature;// 6 bits: PC signature
};

std::vector<std::vector<block_state_t>> blocks(LLC_SETS, std::vector<block_state_t>(LLC_WAYS));

// SHiP-lite table: 2048 entries, 2 bits each
std::vector<uint8_t> ship_table(SHIP_SIG_ENTRIES, SHIP_COUNTER_INIT);

// DRRIP set-dueling
std::vector<uint8_t> is_srrip_leader(LLC_SETS, 0);
std::vector<uint8_t> is_brrip_leader(LLC_SETS, 0);
uint16_t psel = PSEL_MAX/2;

// Streaming detector: per-set, last STREAM_WINDOW address deltas
std::vector<std::vector<int64_t>> stream_deltas(LLC_SETS, std::vector<int64_t>(STREAM_WINDOW, 0));
std::vector<uint64_t> stream_last_addr(LLC_SETS, 0);
std::vector<uint8_t> stream_ptr(LLC_SETS, 0);

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

// Utility: get SHiP signature from PC
inline uint16_t get_signature(uint64_t PC) {
    return (PC ^ (PC >> 2) ^ (PC >> 5)) & SHIP_SIG_MASK;
}

// Streaming detector: returns true if recent deltas are similar (streaming)
bool is_streaming(uint32_t set, uint64_t paddr) {
    int64_t delta = paddr - stream_last_addr[set];
    stream_deltas[set][stream_ptr[set]] = delta;
    stream_ptr[set] = (stream_ptr[set]+1) % STREAM_WINDOW;
    stream_last_addr[set] = paddr;

    // Check if at least STREAM_DELTA_THRESHOLD out of last STREAM_WINDOW deltas are equal and nonzero
    int64_t ref_delta = stream_deltas[set][0];
    if(ref_delta == 0) return false;
    int count = 1;
    for(int i=1; i<STREAM_WINDOW; i++)
        if(stream_deltas[set][i] == ref_delta)
            count++;
    return (count >= STREAM_DELTA_THRESHOLD);
}

// Initialize replacement state
void InitReplacementState() {
    for(uint32_t s=0; s<LLC_SETS; s++) {
        for(uint32_t w=0; w<LLC_WAYS; w++) {
            blocks[s][w] = {RRPV_MAX, 0};
        }
        stream_last_addr[s] = 0;
        stream_ptr[s] = 0;
        std::fill(stream_deltas[s].begin(), stream_deltas[s].end(), 0);
    }
    std::fill(ship_table.begin(), ship_table.end(), SHIP_COUNTER_INIT);
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
    uint16_t sig = get_signature(PC);

    // Streaming detection: update window
    bool streaming = is_streaming(set, paddr);

    // On hit: set block to MRU, increment SHiP counter
    if(hit) {
        blocks[set][way].rrpv = SRRIP_INSERT;
        blocks[set][way].signature = sig;
        // SHiP: increment outcome counter (max at SHIP_COUNTER_MAX)
        if(ship_table[sig] < SHIP_COUNTER_MAX)
            ship_table[sig]++;
        // DRRIP set-dueling: update PSEL for leader sets
        if(is_srrip_leader[set] && psel < PSEL_MAX)
            psel++;
        if(is_brrip_leader[set] && psel > 0)
            psel--;
        return;
    }

    // On fill/replace: SHiP outcome update for victim block
    uint16_t victim_sig = blocks[set][way].signature;
    if(ship_table[victim_sig] > 0)
        ship_table[victim_sig]--;

    // Decide insertion RRPV
    uint8_t ins_rrpv;
    if(streaming) {
        // Streaming detected: bypass or insert at distant RRPV
        ins_rrpv = BRRIP_INSERT;
    } else if(is_srrip_leader[set]) {
        ins_rrpv = SRRIP_INSERT;
    } else if(is_brrip_leader[set]) {
        ins_rrpv = BRRIP_INSERT;
    } else {
        // SHiP bias: if signature counter high, insert at MRU; else at distant
        if(ship_table[sig] >= (SHIP_COUNTER_MAX/2))
            ins_rrpv = SRRIP_INSERT;
        else
            ins_rrpv = BRRIP_INSERT;
    }

    blocks[set][way].rrpv = ins_rrpv;
    blocks[set][way].signature = sig;
}

// Print end-of-simulation statistics
void PrintStats() {
    int ship_high = 0, ship_low = 0;
    for(size_t i=0; i<ship_table.size(); i++) {
        if(ship_table[i] >= (SHIP_COUNTER_MAX/2))
            ship_high++;
        else
            ship_low++;
    }
    std::cout << "SHiP-Lite+Streaming: SHiP high=" << ship_high << " low=" << ship_low << std::endl;
    std::cout << "SHiP-Lite+Streaming: PSEL=" << psel << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // No periodic stats needed
}