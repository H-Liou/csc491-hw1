#include <vector>
#include <cstdint>
#include <cstring>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- Metadata structures ---
// 2 bits RRPV per block
uint8_t rrpv[LLC_SETS][LLC_WAYS];

// 2 bits dead-block counter per block
uint8_t dead_block[LLC_SETS][LLC_WAYS];

// 6 bits PC signature + 2 bits outcome per block
uint8_t pc_sig[LLC_SETS][LLC_WAYS]; // 6 bits
uint8_t sig_outcome[LLC_SETS][64];  // 2 bits per signature, 64 entries per set

// 2 bits streaming confidence per set
uint8_t stream_conf[LLC_SETS];

// DIP: 64 leader sets per policy, 10-bit PSEL
#define NUM_LEADER_SETS 64
#define PSEL_MAX 1023
uint16_t psel = PSEL_MAX/2;
std::vector<uint16_t> leader_sets_srrip, leader_sets_bip;

// Streaming detector: last address per set, stride count
uint64_t last_addr[LLC_SETS];
int last_stride[LLC_SETS];

// Decay epoch counter for dead-block
uint64_t global_epoch = 0;
const uint64_t EPOCH_LEN = 100000; // decay every 100k accesses

// Helper: hash PC to 6 bits
inline uint8_t get_sig(uint64_t PC) {
    return (PC ^ (PC >> 9) ^ (PC >> 15)) & 0x3F;
}

// Helper: choose leader sets for DIP
void init_leader_sets() {
    leader_sets_srrip.clear();
    leader_sets_bip.clear();
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i) {
        leader_sets_srrip.push_back(i);
        leader_sets_bip.push_back(LLC_SETS-NUM_LEADER_SETS+i);
    }
}

// --- API Functions ---
void InitReplacementState() {
    memset(rrpv, 3, sizeof(rrpv));
    memset(dead_block, 0, sizeof(dead_block));
    memset(pc_sig, 0, sizeof(pc_sig));
    memset(sig_outcome, 1, sizeof(sig_outcome)); // optimistic: 1/3 means some reuse
    memset(stream_conf, 0, sizeof(stream_conf));
    memset(last_addr, 0, sizeof(last_addr));
    memset(last_stride, 0, sizeof(last_stride));
    init_leader_sets();
    psel = PSEL_MAX/2;
    global_epoch = 0;
}

uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Find the way with RRPV==3, prefer dead blocks
    for (int r = 3; r >= 0; --r) {
        for (int way = 0; way < LLC_WAYS; ++way) {
            if (rrpv[set][way] == r) {
                // Prefer dead-block
                if (dead_block[set][way] >= 2 || r == 3)
                    return way;
            }
        }
    }
    // Else, pick random
    return 0;
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
    // Update streaming detector
    int stride = (last_addr[set]) ? (int)(paddr - last_addr[set]) : 0;
    if (stride != 0 && abs(stride) < (512*LLC_WAYS)) {
        if (stride == last_stride[set])
            stream_conf[set] = std::min(stream_conf[set]+1, (uint8_t)3);
        else
            stream_conf[set] = std::max(stream_conf[set]-1, (uint8_t)0);
        last_stride[set] = stride;
    } else {
        stream_conf[set] = std::max(stream_conf[set]-1, (uint8_t)0);
        last_stride[set] = 0;
    }
    last_addr[set] = paddr;

    // Get PC signature, update outcome
    uint8_t sig = get_sig(PC);
    if (hit) {
        sig_outcome[set][sig] = std::min(sig_outcome[set][sig]+1, (uint8_t)3); // increment reuse
        dead_block[set][way] = 0;
    } else {
        dead_block[set][way] = std::min(dead_block[set][way]+1, (uint8_t)3);
    }
    pc_sig[set][way] = sig;

    // DRRIP/DIP set-dueling
    bool is_leader_srrip = false, is_leader_bip = false;
    for (auto s : leader_sets_srrip) if (set == s) is_leader_srrip = true;
    for (auto s : leader_sets_bip) if (set == s) is_leader_bip = true;

    // Leader sets: update PSEL
    if (is_leader_srrip && !hit) psel = std::min(psel+1, (uint16_t)PSEL_MAX);
    if (is_leader_bip && hit)    psel = std::max(psel-1, (uint16_t)0);

    // Periodic dead-block decay
    global_epoch++;
    if (global_epoch % EPOCH_LEN == 0) {
        for (uint32_t s = 0; s < LLC_SETS; ++s)
            for (int w = 0; w < LLC_WAYS; ++w)
                dead_block[s][w] = dead_block[s][w] / 2;
    }

    // On fill: set new RRPV based on predictors
    if (!hit) {
        uint8_t insert_rrpv = 3; // default distant
        // Streaming detector: high confidence triggers distant/bypass
        if (stream_conf[set] >= 2) {
            insert_rrpv = 3;
        } else {
            // SHiP-lite: signature reuse
            if (sig_outcome[set][sig] >= 2)
                insert_rrpv = 2; // recent reuse
            // Dead-block: high confidence triggers distant
            if (dead_block[set][way] >= 2)
                insert_rrpv = 3;
        }
        // DIP global: SRRIP or BIP
        bool use_srrip = false;
        if (is_leader_srrip) use_srrip = true;
        else if (is_leader_bip) use_srrip = false;
        else use_srrip = (psel < PSEL_MAX/2);

        if (!use_srrip) {
            // BIP: insert most at distant (3), occasionally at 2
            static uint64_t bip_ctr = 0;
            if ((++bip_ctr % 32) == 0) insert_rrpv = 2;
            else insert_rrpv = 3;
        }
        rrpv[set][way] = insert_rrpv;
    } else {
        rrpv[set][way] = 0; // reset on hit
    }
}

void PrintStats() {
    // Optionally print dead-block distribution, streaming confidence, etc.
}

void PrintStats_Heartbeat() {
    // Optionally print periodic status
}