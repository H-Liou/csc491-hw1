#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// DIP set-dueling parameters
#define NUM_LEADER_SETS 64
#define PSEL_BITS 10
#define PSEL_MAX ((1 << PSEL_BITS) - 1)
#define BIP_PROB 32 // 1/32 MRU insertion for BIP

// SHiP-lite parameters
#define SHIP_SIG_BITS 6
#define SHIP_SIG_MASK ((1 << SHIP_SIG_BITS)-1)
#define SHIP_CTR_BITS 2
#define SHIP_TABLE_SIZE (1 << SHIP_SIG_BITS)

// Streaming detector
#define STREAM_HIST_LEN 4
#define STREAM_DELTA_THR 3

// Per-block state
struct block_state_t {
    uint8_t rrpv;       // 2 bits
    uint8_t ship_sig;   // 6 bits
};

std::vector<std::vector<block_state_t>> blocks(LLC_SETS, std::vector<block_state_t>(LLC_WAYS));

// SHiP-lite outcome table
std::vector<uint8_t> ship_table(SHIP_TABLE_SIZE, 1); // 2-bit counters, weakly reused

// DIP set-dueling
uint16_t psel = PSEL_MAX/2;
std::vector<uint8_t> is_leader(LLC_SETS, 0); // 0: follower, 1: LIP leader, 2: BIP leader

// Streaming detector state
struct stream_set_t {
    uint64_t prev_addr;
    int32_t deltas[STREAM_HIST_LEN];
    int ptr;
    bool streaming;
};
std::vector<stream_set_t> stream_sets(LLC_SETS);

// Utility: compute SHiP signature (bits [6:11] of PC)
inline uint8_t ship_signature(uint64_t PC) {
    return (PC >> 6) & SHIP_SIG_MASK;
}

// Initialize replacement state
void InitReplacementState() {
    for(uint32_t s=0; s<LLC_SETS; s++)
        for(uint32_t w=0; w<LLC_WAYS; w++)
            blocks[s][w] = {3, 0}; // RRPV max, sig 0

    std::fill(ship_table.begin(), ship_table.end(), 1);

    // Assign leader sets for DIP
    for(uint32_t i=0; i<NUM_LEADER_SETS; i++) {
        is_leader[i] = 1; // LIP leader
        is_leader[LLC_SETS-1-i] = 2; // BIP leader
    }

    // Streaming detector
    for(uint32_t s=0; s<LLC_SETS; s++) {
        stream_sets[s].prev_addr = 0;
        memset(stream_sets[s].deltas, 0, sizeof(stream_sets[s].deltas));
        stream_sets[s].ptr = 0;
        stream_sets[s].streaming = false;
    }
    psel = PSEL_MAX/2;
}

// Streaming detection logic
inline void update_streaming(uint32_t set, uint64_t paddr) {
    stream_set_t &st = stream_sets[set];
    if(st.prev_addr != 0) {
        int32_t delta = (int32_t)(paddr - st.prev_addr);
        st.deltas[st.ptr] = delta;
        st.ptr = (st.ptr + 1) % STREAM_HIST_LEN;
        int cnt = 0;
        int32_t ref = st.deltas[(st.ptr+STREAM_HIST_LEN-1)%STREAM_HIST_LEN];
        for(int i=0;i<STREAM_HIST_LEN;i++) if(st.deltas[i]==ref) cnt++;
        st.streaming = (cnt >= STREAM_DELTA_THR);
    }
    st.prev_addr = paddr;
}

// Find victim in the set (SRRIP)
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Streaming detection
    update_streaming(set, paddr);

    // SRRIP victim selection
    while (true) {
        for(uint32_t w=0; w<LLC_WAYS; w++)
            if(blocks[set][w].rrpv == 3)
                return w;
        // Increment RRPV of all blocks
        for(uint32_t w=0; w<LLC_WAYS; w++)
            if(blocks[set][w].rrpv < 3)
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
    update_streaming(set, paddr);

    uint8_t sig = ship_signature(PC);

    if(hit) {
        // On hit: promote block, update SHiP outcome
        blocks[set][way].rrpv = 0;
        if(ship_table[sig] < ((1<<SHIP_CTR_BITS)-1))
            ship_table[sig]++;
    } else {
        // On fill/replace
        bool streaming = stream_sets[set].streaming;
        uint8_t ins_rrpv = 3;
        bool bypass = false;

        // Streaming: bypass with 75% probability, else insert at distant RRPV
        if(streaming) {
            bypass = (rand()%4 < 3);
            ins_rrpv = 3;
        } else {
            // DIP set-dueling: leader sets force LIP/BIP, followers use psel
            if(is_leader[set] == 1) {
                // LIP: always insert at LRU
                ins_rrpv = 3;
            } else if(is_leader[set] == 2) {
                // BIP: insert at LRU, 1/32 at MRU
                ins_rrpv = (rand()%BIP_PROB == 0) ? 0 : 3;
            } else {
                // Follower sets: pick based on psel
                if(psel >= (PSEL_MAX/2)) {
                    // BIP
                    ins_rrpv = (rand()%BIP_PROB == 0) ? 0 : 3;
                } else {
                    // LIP
                    ins_rrpv = 3;
                }
            }
            // SHiP-lite: if PC signature is highly reused, override to MRU
            if(ship_table[sig] >= 2) {
                ins_rrpv = 0;
            }
        }

        if(!bypass) {
            blocks[set][way].rrpv = ins_rrpv;
            blocks[set][way].ship_sig = sig;
        }

        // DIP set-dueling: update psel
        if(is_leader[set] == 1) {
            // LIP leader: increment psel on hit, decrement on miss
            if(hit && psel < PSEL_MAX) psel++;
            else if(!hit && psel > 0) psel--;
        } else if(is_leader[set] == 2) {
            // BIP leader: decrement psel on hit, increment on miss
            if(hit && psel > 0) psel--;
            else if(!hit && psel < PSEL_MAX) psel++;
        }

        // On replacement, update SHiP outcome for victim block
        uint8_t victim_sig = blocks[set][way].ship_sig;
        if(ship_table[victim_sig] > 0)
            ship_table[victim_sig]--;
    }
}

void PrintStats() {
    // Print SHiP table summary
    int reused=0, total=0;
    for(auto ctr : ship_table) {
        if(ctr >= 2) reused++;
        total++;
    }
    std::cout << "DSSH: SHiP reused sigs=" << reused << "/" << total << "  PSEL=" << psel << std::endl;
}
void PrintStats_Heartbeat() { }