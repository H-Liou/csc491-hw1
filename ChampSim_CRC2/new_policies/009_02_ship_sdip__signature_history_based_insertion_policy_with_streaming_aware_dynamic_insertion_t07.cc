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
#define SHIP_INSERT_LRU RRPV_MAX
#define SHIP_INSERT_MRU 0

// SHiP-lite: signature table
#define SIGNATURE_BITS 9
#define SHIP_SIG_ENTRIES 512
#define SHIP_SIG_MASK (SHIP_SIG_ENTRIES-1)
#define SHIP_CNTR_BITS 2
#define SHIP_CNTR_MAX ((1<<SHIP_CNTR_BITS)-1)
#define SHIP_CNTR_THRESHOLD 1 // >=1 means reuse

// Streaming detector
#define STREAM_WINDOW 8
#define STREAM_DELTA_THRESHOLD 6

// DIP set-dueling
#define DIP_LEADER_SETS 32
#define DIP_PSEL_BITS 10
#define DIP_PSEL_MAX ((1<<DIP_PSEL_BITS)-1)
#define DIP_LRU 0
#define DIP_SHIP 1

struct block_state_t {
    uint8_t rrpv;          // 2b RRIP
    uint16_t signature;    // 9b signature (PC hash)
};

std::vector<std::vector<block_state_t>> blocks(LLC_SETS, std::vector<block_state_t>(LLC_WAYS));

// SHiP signature table
struct ship_sig_entry_t {
    uint8_t reuse_cntr;    // 2b counter
};
std::vector<ship_sig_entry_t> ship_sig_table(SHIP_SIG_ENTRIES);

// Streaming detector: per-set
struct stream_state_t {
    uint64_t last_addr;
    int8_t deltas[STREAM_WINDOW];
    uint8_t idx;
    uint8_t stream_flag;
};
std::vector<stream_state_t> stream_state(LLC_SETS);

// DIP set-dueling
std::vector<uint8_t> dip_leader_type(LLC_SETS, DIP_SHIP); // 0: LRU, 1: SHIP
uint32_t psel = DIP_PSEL_MAX / 2; // 10b PSEL counter

uint64_t global_access = 0;

// Utility: PC signature hash
inline uint16_t ship_hash_sig(uint64_t PC) {
    return champsim_crc2(PC, 0) & ((1<<SIGNATURE_BITS)-1);
}

// Initialize replacement state
void InitReplacementState() {
    for(uint32_t s=0; s<LLC_SETS; s++) {
        for(uint32_t w=0; w<LLC_WAYS; w++)
            blocks[s][w] = {RRPV_MAX, 0};
        stream_state[s] = {0, {0}, 0, 0};
        dip_leader_type[s] = DIP_SHIP;
    }
    // DIP: choose leader sets
    for(uint32_t i=0; i<DIP_LEADER_SETS/2; i++)
        dip_leader_type[i] = DIP_LRU;
    for(uint32_t i=DIP_LEADER_SETS/2; i<DIP_LEADER_SETS; i++)
        dip_leader_type[i] = DIP_SHIP;
    for(uint32_t i=0; i<SHIP_SIG_ENTRIES; i++)
        ship_sig_table[i] = {0};
    psel = DIP_PSEL_MAX/2;
    global_access = 0;
}

// Streaming detector
void update_stream_detector(uint32_t set, uint64_t paddr) {
    stream_state_t &st = stream_state[set];
    int8_t delta = 0;
    if(st.last_addr)
        delta = (int8_t)((paddr - st.last_addr) >> 6);
    st.deltas[st.idx % STREAM_WINDOW] = delta;
    st.idx++;
    st.last_addr = paddr;
    int pos=0, neg=0;
    for(uint8_t i=0;i<STREAM_WINDOW;i++) {
        if(st.deltas[i]==1) pos++;
        else if(st.deltas[i]==-1) neg++;
    }
    st.stream_flag = ((pos >= STREAM_DELTA_THRESHOLD || neg >= STREAM_DELTA_THRESHOLD) ? 1 : 0);
}

// Find victim in the set (standard RRIP)
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Streaming: prefer to evict blocks with distant RRPV
    if(stream_state[set].stream_flag) {
        for(uint32_t w=0; w<LLC_WAYS; w++)
            if(blocks[set][w].rrpv == RRPV_MAX)
                return w;
    }
    // RRIP victim selection
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
    global_access++;
    update_stream_detector(set, paddr);

    uint16_t sig = ship_hash_sig(PC);
    ship_sig_entry_t &sig_entry = ship_sig_table[sig & SHIP_SIG_MASK];

    bool is_leader = (set < DIP_LEADER_SETS);

    // On hit: set block to MRU, increment signature counter
    if(hit) {
        blocks[set][way].rrpv = SHIP_INSERT_MRU;
        if(sig_entry.reuse_cntr < SHIP_CNTR_MAX)
            sig_entry.reuse_cntr++;
        return;
    }

    // On eviction: decrement signature counter for victim block's signature
    uint16_t victim_sig = blocks[set][way].signature;
    ship_sig_entry_t &victim_entry = ship_sig_table[victim_sig & SHIP_SIG_MASK];
    if(victim_entry.reuse_cntr > 0)
        victim_entry.reuse_cntr--;

    // Decide insertion depth
    uint8_t ins_rrpv = SHIP_INSERT_MRU;
    if(stream_state[set].stream_flag) {
        ins_rrpv = SHIP_INSERT_LRU; // streaming: insert at distant RRPV
    } else if(is_leader && dip_leader_type[set] == DIP_LRU) {
        ins_rrpv = SHIP_INSERT_LRU; // LRU policy in leader sets
    } else if(is_leader && dip_leader_type[set] == DIP_SHIP) {
        ins_rrpv = (sig_entry.reuse_cntr >= SHIP_CNTR_THRESHOLD) ? SHIP_INSERT_MRU : SHIP_INSERT_LRU;
    } else {
        // Non-leader sets: select policy based on PSEL
        if(psel > DIP_PSEL_MAX/2)
            ins_rrpv = (sig_entry.reuse_cntr >= SHIP_CNTR_THRESHOLD) ? SHIP_INSERT_MRU : SHIP_INSERT_LRU;
        else
            ins_rrpv = SHIP_INSERT_LRU;
    }

    // Update PSEL: Only on fills to leader sets, based on hit/miss
    if(is_leader) {
        if(dip_leader_type[set] == DIP_SHIP) {
            if(hit && psel < DIP_PSEL_MAX) psel++;
        } else if(dip_leader_type[set] == DIP_LRU) {
            if(hit && psel > 0) psel--;
        }
    }

    // Insert block
    blocks[set][way].rrpv = ins_rrpv;
    blocks[set][way].signature = sig;
}

// Print end-of-simulation statistics
void PrintStats() {
    int streaming_sets = 0, lru_inserts = 0, mru_inserts = 0;
    for(uint32_t s=0; s<LLC_SETS; s++) {
        if(stream_state[s].stream_flag)
            streaming_sets++;
        for(uint32_t w=0; w<LLC_WAYS; w++) {
            if(blocks[s][w].rrpv == SHIP_INSERT_MRU)
                mru_inserts++;
            if(blocks[s][w].rrpv == SHIP_INSERT_LRU)
                lru_inserts++;
        }
    }
    std::cout << "SHiP-SDIP: Streaming sets = " << streaming_sets << std::endl;
    std::cout << "SHiP-SDIP: MRU inserts = " << mru_inserts << ", LRU inserts = " << lru_inserts << std::endl;
    std::cout << "SHiP-SDIP: Final PSEL = " << psel << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    // No periodic stats needed
}