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
    uint8_t rrpv;           // 2 bits: RRIP value
    uint8_t addr_reuse;     // 2 bits: address-based dead-block counter
    uint8_t pc_sig;         // 6 bits: PC signature
};

struct SHiPEntry {
    uint8_t outcome;        // 2 bits: reuse counter
};

struct SetStream {
    int64_t last_addr;      // Last filled address
    int64_t last_delta;     // Last delta
    uint8_t stream_conf;    // 2 bits: streaming confidence
};

// --- Global state ---
BlockMeta block_meta[LLC_SETS][LLC_WAYS];
SHiPEntry ship_table[4096]; // 6-bit signature: 64*64 entries
SetStream set_stream[LLC_SETS];

uint16_t psel = 512; // 10 bits: DRRIP set-dueling selector

// Leader sets for SRRIP/BRRIP
const int NUM_LEADER_SETS = 64;
std::vector<uint32_t> srrip_leader_sets;
std::vector<uint32_t> brrip_leader_sets;

// Helper: get 6-bit PC signature
inline uint16_t get_pc_sig(uint64_t PC) {
    return (PC ^ (PC >> 6)) & 0x3F;
}

// Helper: get SHiP table index
inline uint16_t ship_index(uint8_t pc_sig) {
    return pc_sig;
}

// Helper: is leader set
inline bool is_srrip_leader(uint32_t set) {
    return std::find(srrip_leader_sets.begin(), srrip_leader_sets.end(), set) != srrip_leader_sets.end();
}
inline bool is_brrip_leader(uint32_t set) {
    return std::find(brrip_leader_sets.begin(), brrip_leader_sets.end(), set) != brrip_leader_sets.end();
}

// --- Initialization ---
void InitReplacementState() {
    // Initialize block metadata
    memset(block_meta, 0, sizeof(block_meta));
    memset(ship_table, 0, sizeof(ship_table));
    memset(set_stream, 0, sizeof(set_stream));
    psel = 512;

    // Randomly assign leader sets
    srrip_leader_sets.clear();
    brrip_leader_sets.clear();
    for (uint32_t i = 0; i < NUM_LEADER_SETS; ++i) {
        srrip_leader_sets.push_back(i);
        brrip_leader_sets.push_back(LLC_SETS - 1 - i);
    }
}

// --- Streaming detector ---
bool is_streaming(uint32_t set, uint64_t paddr) {
    SetStream &ss = set_stream[set];
    int64_t delta = (ss.last_addr == -1) ? 0 : (int64_t)paddr - ss.last_addr;
    bool monotonic = (ss.last_delta != 0) && (delta == ss.last_delta);
    if (monotonic && delta != 0) {
        if (ss.stream_conf < 3) ss.stream_conf++;
    } else {
        if (ss.stream_conf > 0) ss.stream_conf--;
    }
    ss.last_delta = delta;
    ss.last_addr = paddr;
    return ss.stream_conf >= 2;
}

// --- Victim selection ---
uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Streaming bypass: if streaming detected, prefer distant RRPV or bypass
    bool streaming = is_streaming(set, paddr);

    // Standard RRIP victim selection
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (block_meta[set][way].rrpv == 3) {
                return way;
            }
        }
        // Increment RRPV of all blocks
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (block_meta[set][way].rrpv < 3)
                block_meta[set][way].rrpv++;
        }
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
    BlockMeta &bm = block_meta[set][way];
    uint8_t pc_sig = get_pc_sig(PC);
    uint16_t ship_idx = ship_index(pc_sig);

    // Streaming detector update
    bool streaming = is_streaming(set, paddr);

    // Dead-block predictor update (address reuse)
    if (!hit) {
        // On eviction, increment dead-block counter if not reused
        if (bm.addr_reuse < 3) bm.addr_reuse++;
    } else {
        // On hit, decay dead-block counter
        if (bm.addr_reuse > 0) bm.addr_reuse--;
    }

    // SHiP outcome update
    if (hit) {
        if (ship_table[ship_idx].outcome < 3) ship_table[ship_idx].outcome++;
    } else {
        if (ship_table[ship_idx].outcome > 0) ship_table[ship_idx].outcome--;
    }

    // Insertion policy
    uint8_t insert_rrpv = 3; // default distant
    bool high_ship = (ship_table[ship_idx].outcome >= 2);
    bool addr_live = (bm.addr_reuse == 0);

    // DRRIP set-dueling
    bool use_srrip = false;
    if (is_srrip_leader(set)) use_srrip = true;
    else if (is_brrip_leader(set)) use_srrip = false;
    else use_srrip = (psel >= 512);

    // Streaming: bypass or distant insertion
    if (streaming) {
        insert_rrpv = 3;
    } else if (high_ship || addr_live) {
        insert_rrpv = use_srrip ? 2 : 3;
    } else {
        insert_rrpv = 3;
    }

    // Update PSEL for leader sets
    if (is_srrip_leader(set) && hit) {
        if (psel < 1023) psel++;
    } else if (is_brrip_leader(set) && hit) {
        if (psel > 0) psel--;
    }

    // Fill block metadata
    bm.rrpv = insert_rrpv;
    bm.pc_sig = pc_sig;
    // Reset address reuse counter on fill
    bm.addr_reuse = 0;
}

// --- Statistics ---
void PrintStats() {
    std::cout << "SAHSB: SHiP-Address Hybrid + Streaming Bypass stats" << std::endl;
}
void PrintStats_Heartbeat() {
    // Optional: print periodic stats
}