#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// ---- RRIP Metadata ----
uint8_t rrpv[LLC_SETS][LLC_WAYS]; // 2 bits per block

// ---- SHiP-lite: per-line PC signature (6 bits) ----
uint8_t pc_sig[LLC_SETS][LLC_WAYS]; // 6 bits per block

// ---- SHiP outcome table: 4096 entries, 2 bits each ----
#define SHIP_ENTRIES 4096
uint8_t ship_ctr[SHIP_ENTRIES]; // 2 bits per entry

// ---- Dead-block counter: 2 bits per line ----
uint8_t dead_ctr[LLC_SETS][LLC_WAYS]; // 2 bits per block

// ---- DIP set-dueling: 64 leader sets for LIP, 64 for BIP ----
#define NUM_LEADER_SETS 64
uint8_t is_lip_leader[LLC_SETS];
uint8_t is_bip_leader[LLC_SETS];

// ---- PSEL counter: 10 bits ----
uint16_t psel = 512; // 0..1023, LIP if psel >= 512, else BIP

// ---- Other bookkeeping ----
uint64_t access_counter = 0;
#define DECAY_PERIOD 100000

// Helper: hash PC to 6 bits
inline uint16_t get_pc_sig(uint64_t PC) {
    return (PC ^ (PC >> 6) ^ (PC >> 12)) & 0x3F; // 6 bits
}

// Helper: hash PC to SHiP table index (12 bits)
inline uint16_t get_ship_idx(uint64_t PC) {
    return (PC ^ (PC >> 13) ^ (PC >> 23)) & 0xFFF; // 12 bits
}

// Helper: assign leader sets for set-dueling
void assign_leader_sets() {
    memset(is_lip_leader, 0, sizeof(is_lip_leader));
    memset(is_bip_leader, 0, sizeof(is_bip_leader));
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i) {
        is_lip_leader[i] = 1;
        is_bip_leader[LLC_SETS - 1 - i] = 1;
    }
}

void InitReplacementState() {
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            rrpv[set][way] = 3;
            pc_sig[set][way] = 0;
            dead_ctr[set][way] = 0;
        }
    }
    for (uint32_t i = 0; i < SHIP_ENTRIES; ++i)
        ship_ctr[i] = 1; // weakly dead
    assign_leader_sets();
    psel = 512;
    access_counter = 0;
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
    // Prefer invalid block
    for (uint32_t way = 0; way < LLC_WAYS; ++way)
        if (!current_set[way].valid)
            return way;

    // RRIP: select block with max RRPV (3)
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] == 3)
                return way;
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (rrpv[set][way] < 3)
                rrpv[set][way]++;
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
    access_counter++;

    // ---- SHiP signature and outcome update ----
    uint16_t sig = get_pc_sig(PC);
    uint16_t ship_idx = get_ship_idx(PC);

    if (hit) {
        // On hit, increase reuse confidence for signature
        if (ship_ctr[ship_idx] < 3)
            ship_ctr[ship_idx]++;
        rrpv[set][way] = 0; // promote to MRU
        // Block reused: reset dead-block counter
        dead_ctr[set][way] = 0;
    } else {
        // On miss, decrease reuse confidence
        if (ship_ctr[ship_idx] > 0)
            ship_ctr[ship_idx]--;
        // Block inserted: keep dead-block counter as is
    }
    pc_sig[set][way] = sig;

    // ---- DIP set-dueling: determine insertion policy ----
    bool use_lip = true;
    if (is_lip_leader[set])
        use_lip = true;
    else if (is_bip_leader[set])
        use_lip = false;
    else
        use_lip = (psel >= 512);

    // ---- Dead-block counter: bypass insertion if saturated ----
    if (dead_ctr[set][way] == 3) {
        // Predicted dead: insert at LRU (RRPV=3)
        rrpv[set][way] = 3;
    } else {
        // SHiP outcome: insert at MRU if high reuse, else DIP policy
        if (ship_ctr[ship_idx] >= 2) {
            rrpv[set][way] = 0; // high reuse, insert at MRU
        } else {
            if (use_lip) {
                rrpv[set][way] = 3; // LIP: always insert at LRU
            } else {
                // BIP: insert at LRU with 1/32 probability, else MRU
                if ((access_counter & 0x1F) == 0)
                    rrpv[set][way] = 3;
                else
                    rrpv[set][way] = 0;
            }
        }
    }

    // ---- Set-dueling: update PSEL on leader sets ----
    if (is_lip_leader[set]) {
        if (hit && !dead_ctr[set][way] && rrpv[set][way] == 3) {
            // LIP leader: reward if hit on LRU insertion
            if (psel < 1023) psel++;
        }
    } else if (is_bip_leader[set]) {
        if (hit && !dead_ctr[set][way] && (rrpv[set][way] == 0)) {
            // BIP leader: reward if hit on MRU insertion
            if (psel > 0) psel--;
        }
    }

    // ---- Dead-block counter update on victim ----
    // If the victim block was not reused (RRPV==3 and not hit), increment dead_ctr
    for (uint32_t vway = 0; vway < LLC_WAYS; ++vway) {
        if (victim_addr == 0) break; // skip if not available
        if (rrpv[set][vway] == 3 && !hit) {
            if (dead_ctr[set][vway] < 3)
                dead_ctr[set][vway]++;
        }
    }

    // ---- Periodic decay of SHiP outcome and dead-block counters ----
    if (access_counter % DECAY_PERIOD == 0) {
        for (uint32_t i = 0; i < SHIP_ENTRIES; ++i)
            if (ship_ctr[i] > 0)
                ship_ctr[i]--;
        for (uint32_t set = 0; set < LLC_SETS; ++set)
            for (uint32_t way = 0; way < LLC_WAYS; ++way)
                if (dead_ctr[set][way] > 0)
                    dead_ctr[set][way]--;
    }
}

// Print end-of-simulation statistics
void PrintStats() {
    int high_reuse_sigs = 0;
    for (uint32_t i = 0; i < SHIP_ENTRIES; ++i)
        if (ship_ctr[i] >= 2) high_reuse_sigs++;
    int dead_blocks = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (dead_ctr[set][way] == 3) dead_blocks++;
    std::cout << "SHiP-DBC-DIP Policy: SHiP-Lite + Dead-Block Counter + DIP Set-Dueling" << std::endl;
    std::cout << "High-reuse signatures: " << high_reuse_sigs << "/" << SHIP_ENTRIES << std::endl;
    std::cout << "Dead blocks (counter==3): " << dead_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "PSEL value: " << psel << std::endl;
}

// Print periodic (heartbeat) statistics
void PrintStats_Heartbeat() {
    int high_reuse_sigs = 0;
    for (uint32_t i = 0; i < SHIP_ENTRIES; ++i)
        if (ship_ctr[i] >= 2) high_reuse_sigs++;
    int dead_blocks = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (dead_ctr[set][way] == 3) dead_blocks++;
    std::cout << "High-reuse signatures (heartbeat): " << high_reuse_sigs << "/" << SHIP_ENTRIES << std::endl;
    std::cout << "Dead blocks (counter==3, heartbeat): " << dead_blocks << "/" << (LLC_SETS * LLC_WAYS) << std::endl;
    std::cout << "PSEL value (heartbeat): " << psel << std::endl;
}