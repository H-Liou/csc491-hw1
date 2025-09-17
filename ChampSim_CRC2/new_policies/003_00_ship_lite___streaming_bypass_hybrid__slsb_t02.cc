#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// SHiP-lite parameters
#define SIG_BITS 5
#define SIG_MASK ((1<<SIG_BITS)-1)
#define OUTCOME_BITS 2
#define OUTCOME_MAX ((1<<OUTCOME_BITS)-1)
#define OUTCOME_THRESH 2 // >=2 means "high reuse"

// Streaming detector
#define STREAM_HIST_LEN 4
#define STREAM_DELTA_THR 3

// RRIP parameters
#define RRPV_BITS 2
#define RRPV_MAX ((1<<RRPV_BITS)-1)
#define MRU_RRPV 0
#define LRU_RRPV RRPV_MAX

// Per-block state
struct block_state_t {
    uint8_t rrpv;      // 2b
    uint8_t sig;       // 5b
};

std::vector<std::vector<block_state_t>> blocks(LLC_SETS, std::vector<block_state_t>(LLC_WAYS));

// SHiP-lite signature table: 32 entries per set, 2b outcome counter each
#define SIG_TABLE_SIZE 32
struct sig_entry_t {
    uint8_t sig;          // 5b
    uint8_t outcome_ctr;  // 2b
};
std::vector<std::vector<sig_entry_t>> sig_table(LLC_SETS, std::vector<sig_entry_t>(SIG_TABLE_SIZE));

// Streaming detector state per set
struct stream_set_t {
    uint64_t prev_addr;
    int32_t deltas[STREAM_HIST_LEN];
    int ptr;
    bool streaming;
};
std::vector<stream_set_t> stream_sets(LLC_SETS);

// Utility: hash PC to signature
inline uint8_t get_sig(uint64_t PC) {
    return champsim_crc2(PC, 0x1234) & SIG_MASK;
}

// Find signature entry in table
inline int find_sig_entry(uint32_t set, uint8_t sig) {
    for(int i=0;i<SIG_TABLE_SIZE;i++)
        if(sig_table[set][i].sig == sig)
            return i;
    return -1;
}

// Streaming detection logic
inline void update_streaming(uint32_t set, uint64_t paddr) {
    stream_set_t &st = stream_sets[set];
    if (st.prev_addr != 0) {
        int32_t delta = (int32_t)(paddr - st.prev_addr);
        st.deltas[st.ptr] = delta;
        st.ptr = (st.ptr + 1) % STREAM_HIST_LEN;
        // Count matching deltas
        int cnt = 0;
        int32_t ref = st.deltas[(st.ptr+STREAM_HIST_LEN-1)%STREAM_HIST_LEN];
        for(int i=0;i<STREAM_HIST_LEN;i++) if(st.deltas[i]==ref) cnt++;
        st.streaming = (cnt >= STREAM_DELTA_THR);
    }
    st.prev_addr = paddr;
}

void InitReplacementState() {
    for(uint32_t s=0; s<LLC_SETS; s++)
        for(uint32_t w=0; w<LLC_WAYS; w++)
            blocks[s][w] = {RRPV_MAX, 0}; // RRPV max, sig 0

    for(uint32_t s=0; s<LLC_SETS; s++) {
        for(int i=0;i<SIG_TABLE_SIZE;i++)
            sig_table[s][i] = {0, 0};
        stream_sets[s].prev_addr = 0;
        memset(stream_sets[s].deltas, 0, sizeof(stream_sets[s].deltas));
        stream_sets[s].ptr = 0;
        stream_sets[s].streaming = false;
    }
}

// Victim selection: prefer highest RRPV, break ties with lowest outcome counter
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    int victim = -1;
    int max_rrpv = -1;
    int min_outcome = OUTCOME_MAX+1;
    for(uint32_t w=0; w<LLC_WAYS; w++) {
        int rrpv = blocks[set][w].rrpv;
        uint8_t sig = blocks[set][w].sig;
        int idx = find_sig_entry(set, sig);
        int outcome = (idx>=0) ? sig_table[set][idx].outcome_ctr : 0;
        if(rrpv > max_rrpv || (rrpv == max_rrpv && outcome < min_outcome)) {
            max_rrpv = rrpv;
            min_outcome = outcome;
            victim = w;
        }
    }
    if(victim < 0) return 0;
    return victim;
}

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

    uint8_t sig = get_sig(PC);
    int idx = find_sig_entry(set, sig);

    // On hit: increment outcome counter for signature
    if(hit) {
        if(idx < 0) {
            // Insert new entry (LRU replacement)
            int repl = 0;
            for(int i=1;i<SIG_TABLE_SIZE;i++)
                if(sig_table[set][i].outcome_ctr < sig_table[set][repl].outcome_ctr)
                    repl = i;
            sig_table[set][repl] = {sig, 1};
        } else if(sig_table[set][idx].outcome_ctr < OUTCOME_MAX)
            sig_table[set][idx].outcome_ctr++;
        blocks[set][way].rrpv = MRU_RRPV;
        blocks[set][way].sig = sig;
    }
    // On miss/fill/replace
    else {
        bool streaming = stream_sets[set].streaming;
        bool bypass = false;
        uint8_t ins_rrpv = LRU_RRPV;

        if(streaming) {
            bypass = true; // Do not insert streaming blocks
        } else {
            // Use SHiP-lite outcome counter to bias insertion depth
            if(idx >= 0 && sig_table[set][idx].outcome_ctr >= OUTCOME_THRESH)
                ins_rrpv = MRU_RRPV;
            else
                ins_rrpv = LRU_RRPV;
        }

        if(!bypass) {
            blocks[set][way].rrpv = ins_rrpv;
            blocks[set][way].sig = sig;
            // Insert/update signature table entry
            if(idx < 0) {
                int repl = 0;
                for(int i=1;i<SIG_TABLE_SIZE;i++)
                    if(sig_table[set][i].outcome_ctr < sig_table[set][repl].outcome_ctr)
                        repl = i;
                sig_table[set][repl] = {sig, 0};
            }
        }
    }
    // Periodic decay: every 4096 fills, decay all outcome counters
    static uint64_t fill_count = 0;
    fill_count++;
    if((fill_count & 0xFFF) == 0) {
        for(uint32_t s=0; s<LLC_SETS; s++)
            for(int i=0;i<SIG_TABLE_SIZE;i++)
                if(sig_table[s][i].outcome_ctr > 0)
                    sig_table[s][i].outcome_ctr--;
    }
}

void PrintStats() {
    // Print streaming set count and average outcome counter
    int stream_cnt=0;
    int sig_cnt=0;
    int outcome_sum=0;
    for(uint32_t s=0; s<LLC_SETS; s++) {
        if(stream_sets[s].streaming) stream_cnt++;
        for(int i=0;i<SIG_TABLE_SIZE;i++) {
            if(sig_table[s][i].outcome_ctr > 0) {
                sig_cnt++;
                outcome_sum += sig_table[s][i].outcome_ctr;
            }
        }
    }
    std::cout << "SLSB: Streaming sets flagged = " << stream_cnt << "/" << LLC_SETS << std::endl;
    if(sig_cnt)
        std::cout << "SLSB: Avg outcome counter = " << (double)outcome_sum/sig_cnt << std::endl;
}

void PrintStats_Heartbeat() {
    // No periodic stats needed
}