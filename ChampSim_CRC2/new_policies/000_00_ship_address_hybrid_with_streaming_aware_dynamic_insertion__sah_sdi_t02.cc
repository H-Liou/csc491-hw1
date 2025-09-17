#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- Metadata structures ---
struct BlockMeta {
    uint8_t rrpv;        // 2 bits: RRIP value
    uint8_t addr_reuse;  // 2 bits: address-based reuse counter
    uint8_t ship_sig;    // 5 bits: PC signature
};

struct SetMeta {
    uint8_t stream_conf; // 2 bits: streaming confidence
    uint64_t last_addr;  // last filled address (for stride detection)
    int64_t last_delta;  // last stride
};

// SHiP-lite: 32K entries * 2 bits = 8 KiB
#define SHIP_SIG_BITS 5
#define SHIP_TABLE_SIZE (1 << 15) // 32K entries
uint8_t ship_table[SHIP_TABLE_SIZE];

// Per-block metadata: 2048*16 = 32K blocks * 2 bits addr_reuse + 5 bits ship_sig = 7 bits/block = ~28 KiB
BlockMeta block_meta[LLC_SETS][LLC_WAYS];

// Per-set streaming detector: 2048 sets * (2 bits conf + 64 bits addr + 64 bits delta) ≈ 0.5 KiB
SetMeta set_meta[LLC_SETS];

// Set-dueling: 64 leader sets for SRRIP, 64 for BRRIP
#define NUM_LEADER_SETS 64
#define PSEL_MAX 1023
uint16_t psel = PSEL_MAX / 2;

// Map set to leader type
bool is_srrip_leader(uint32_t set) { return set < NUM_LEADER_SETS; }
bool is_brrip_leader(uint32_t set) { return set >= NUM_LEADER_SETS && set < 2 * NUM_LEADER_SETS; }

// --- Helper functions ---
inline uint32_t get_ship_sig(uint64_t PC) {
    // 5-bit signature from PC
    return (PC >> 2) & ((1 << SHIP_SIG_BITS) - 1);
}
inline uint32_t get_ship_idx(uint64_t PC) {
    // 15-bit index from PC
    return (PC >> 2) & (SHIP_TABLE_SIZE - 1);
}

// --- Initialization ---
void InitReplacementState() {
    memset(ship_table, 0, sizeof(ship_table));
    memset(block_meta, 0, sizeof(block_meta));
    memset(set_meta, 0, sizeof(set_meta));
    psel = PSEL_MAX / 2;
}

// --- Streaming detector ---
bool detect_streaming(uint32_t set, uint64_t addr) {
    SetMeta &meta = set_meta[set];
    int64_t delta = int64_t(addr) - int64_t(meta.last_addr);
    bool streaming = false;

    if (meta.last_addr != 0) {
        if (meta.last_delta != 0 && delta == meta.last_delta) {
            if (meta.stream_conf < 3) meta.stream_conf++;
        } else {
            if (meta.stream_conf > 0) meta.stream_conf--;
        }
        if (meta.stream_conf >= 2 && delta != 0) streaming = true;
    }
    meta.last_delta = delta;
    meta.last_addr = addr;
    return streaming;
}

// --- Find victim ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Standard RRIP victim selection
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; way++) {
            if (block_meta[set][way].rrpv == 3)
                return way;
        }
        // Increment all RRPVs
        for (uint32_t way = 0; way < LLC_WAYS; way++)
            if (block_meta[set][way].rrpv < 3)
                block_meta[set][way].rrpv++;
    }
}

// --- Update replacement state ---
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
    BlockMeta &meta = block_meta[set][way];
    uint32_t ship_sig = get_ship_sig(PC);
    uint32_t ship_idx = get_ship_idx(PC);

    // Streaming detection
    bool streaming = detect_streaming(set, paddr);

    // On hit: promote block, update reuse
    if (hit) {
        meta.rrpv = 0;
        meta.addr_reuse = meta.addr_reuse < 3 ? meta.addr_reuse + 1 : 3;
        ship_table[ship_idx] = ship_table[ship_idx] < 3 ? ship_table[ship_idx] + 1 : 3;
    } else {
        // On fill: choose insertion depth
        // Set-dueling: select SRRIP or BRRIP
        bool use_srrip = false;
        if (is_srrip_leader(set)) use_srrip = true;
        else if (is_brrip_leader(set)) use_srrip = false;
        else use_srrip = (psel >= PSEL_MAX / 2);

        // SHiP outcome
        uint8_t ship_outcome = ship_table[ship_idx];
        // Address reuse
        uint8_t addr_reuse = meta.addr_reuse;

        // Streaming: bypass or distant insertion
        if (streaming) {
            meta.rrpv = 3; // distant insertion
        } else if (ship_outcome >= 2 || addr_reuse >= 2) {
            meta.rrpv = use_srrip ? 2 : (rand() % 10 == 0 ? 2 : 3); // SRRIP: 2, BRRIP: mostly 3
        } else {
            meta.rrpv = 3; // distant insertion for poor reuse
        }

        // Update SHiP signature and address reuse
        meta.ship_sig = ship_sig;
        meta.addr_reuse = 0;
    }

    // Set-dueling: update PSEL
    if (!hit) {
        if (is_srrip_leader(set)) {
            if (ship_table[ship_idx] >= 2) psel = psel < PSEL_MAX ? psel + 1 : PSEL_MAX;
        }
        if (is_brrip_leader(set)) {
            if (ship_table[ship_idx] < 2) psel = psel > 0 ? psel - 1 : 0;
        }
    }

    // Dead-block decay: periodically decay address reuse and SHiP outcome
    static uint64_t access_counter = 0;
    access_counter++;
    if ((access_counter & 0xFFF) == 0) { // every 4096 accesses
        for (uint32_t s = 0; s < LLC_SETS; s++) {
            for (uint32_t w = 0; w < LLC_WAYS; w++) {
                if (block_meta[s][w].addr_reuse > 0) block_meta[s][w].addr_reuse--;
            }
        }
        for (uint32_t i = 0; i < SHIP_TABLE_SIZE; i++) {
            if (ship_table[i] > 0) ship_table[i]--;
        }
    }
}

// --- Stats ---
void PrintStats() {}
void PrintStats_Heartbeat() {}