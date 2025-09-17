#include <vector>
#include <cstdint>
#include <cstring>
#include <iostream>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

// --- Metadata sizes ---
// RRPV: 2 bits/line
// SHiP signature: 6 bits/line
// SHiP table: 2K entries x 2 bits = 4 KiB
// Address table: 1K entries x 2 bits = 2 KiB
// Streaming detector: 2 bytes/set = 4 KiB
// PSEL: 10 bits

// Replacement state structures
struct LineMeta {
    uint8_t rrpv;         // 2 bits
    uint8_t ship_sig;     // 6 bits
    uint16_t addr_sig;    // 10 bits (compact address hash)
};

std::vector<std::vector<LineMeta>> repl_meta(LLC_SETS, std::vector<LineMeta>(LLC_WAYS));

// SHiP table: 2K entries, 2 bits each
uint8_t ship_table[2048];

// Address reuse table: 1K entries, 2 bits each
uint8_t addr_table[1024];

// Streaming detector: 2 bytes/set
struct StreamDetect {
    uint64_t last_addr;
    int32_t stride;
    uint8_t stream_count;
    bool streaming;
};
StreamDetect stream_table[LLC_SETS];

// PSEL for set-dueling (SRRIP vs BRRIP)
uint16_t psel = 512;
const uint16_t PSEL_MAX = 1023;
const uint16_t PSEL_MIN = 0;

// Leader sets (first 32 sets for SRRIP, next 32 for BRRIP)
const int NUM_LEADER_SETS = 64;
const int SRRIP_LEADER = 0;
const int BRRIP_LEADER = 32;

// Helper: get SHiP signature (6 bits) from PC
inline uint8_t get_ship_sig(uint64_t PC) {
    return (PC ^ (PC >> 6) ^ (PC >> 12)) & 0x3F;
}

// Helper: get address signature (10 bits) from paddr
inline uint16_t get_addr_sig(uint64_t paddr) {
    return ((paddr >> 6) ^ (paddr >> 12)) & 0x3FF;
}

void InitReplacementState() {
    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            repl_meta[set][way].rrpv = 3;
            repl_meta[set][way].ship_sig = 0;
            repl_meta[set][way].addr_sig = 0;
        }
        stream_table[set].last_addr = 0;
        stream_table[set].stride = 0;
        stream_table[set].stream_count = 0;
        stream_table[set].streaming = false;
    }
    memset(ship_table, 1, sizeof(ship_table));
    memset(addr_table, 1, sizeof(addr_table));
    psel = 512;
}

uint32_t GetVictimInSet(
    uint32_t cpu,
    uint32_t set,
    const BLOCK *current_set,
    uint64_t PC,
    uint64_t paddr,
    uint32_t type
) {
    // Streaming bypass: if streaming detected and both SHiP and addr reuse are low, bypass (return -1)
    StreamDetect &sd = stream_table[set];
    uint8_t ship_sig = get_ship_sig(PC);
    uint16_t addr_sig = get_addr_sig(paddr);

    bool low_ship = ship_table[ship_sig] == 0;
    bool low_addr = addr_table[addr_sig] == 0;
    if (sd.streaming && low_ship && low_addr) {
        return LLC_WAYS; // special value: bypass fill
    }

    // Standard RRIP victim selection
    while (true) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            if (repl_meta[set][way].rrpv == 3)
                return way;
        }
        // Increment all RRPVs
        for (uint32_t way = 0; way < LLC_WAYS; ++way)
            if (repl_meta[set][way].rrpv < 3)
                repl_meta[set][way].rrpv++;
    }
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
    // Streaming detector: update stride and streaming status
    StreamDetect &sd = stream_table[set];
    uint64_t addr_blk = paddr >> 6;
    int32_t new_stride = addr_blk - (sd.last_addr >> 6);
    if (sd.stream_count > 0 && new_stride == sd.stride)
        sd.stream_count++;
    else {
        sd.stride = new_stride;
        sd.stream_count = 1;
    }
    sd.last_addr = paddr;
    if (sd.stream_count >= 8 && sd.stride != 0)
        sd.streaming = true;
    else if (sd.stream_count < 4)
        sd.streaming = false;

    // Update SHiP and address tables
    uint8_t ship_sig = get_ship_sig(PC);
    uint16_t addr_sig = get_addr_sig(paddr);

    if (hit) {
        // On hit, promote RRPV and increment reuse counters
        repl_meta[set][way].rrpv = 0;
        if (ship_table[ship_sig] < 3) ship_table[ship_sig]++;
        if (addr_table[addr_sig] < 3) addr_table[addr_sig]++;
    } else {
        // On miss, set insertion depth based on predictors and streaming
        repl_meta[set][way].ship_sig = ship_sig;
        repl_meta[set][way].addr_sig = addr_sig;

        bool high_ship = ship_table[ship_sig] >= 2;
        bool high_addr = addr_table[addr_sig] >= 2;

        // Set-dueling: leader sets pick SRRIP/BRRIP, others use PSEL
        bool use_brrip = false;
        if (set < NUM_LEADER_SETS) {
            if (set < BRRIP_LEADER) use_brrip = false;
            else use_brrip = true;
        } else {
            use_brrip = (psel >= 512);
        }

        // Streaming region: if streaming, and reuse is low, insert at distant RRPV or bypass
        if (sd.streaming && !(high_ship || high_addr)) {
            repl_meta[set][way].rrpv = 3; // distant insert
        } else if (high_ship || high_addr) {
            repl_meta[set][way].rrpv = 0; // MRU insert
        } else {
            // SRRIP/BRRIP insertion
            repl_meta[set][way].rrpv = use_brrip ? ((rand() % 32 == 0) ? 2 : 3) : 2;
        }

        // Reset reuse counters for new block
        ship_table[ship_sig] = 1;
        addr_table[addr_sig] = 1;
    }

    // Update PSEL for set-dueling
    if (set < NUM_LEADER_SETS) {
        if (hit) {
            if (set < BRRIP_LEADER && psel < PSEL_MAX) psel++;
            else if (set >= BRRIP_LEADER && psel > PSEL_MIN) psel--;
        }
    }
}

void PrintStats() {
    // Optionally print SHiP and address table stats
    uint64_t ship_reuse = 0, addr_reuse = 0;
    for (int i = 0; i < 2048; ++i) ship_reuse += ship_table[i];
    for (int i = 0; i < 1024; ++i) addr_reuse += addr_table[i];
    std::cout << "SHiP table avg reuse: " << (ship_reuse / 2048.0) << std::endl;
    std::cout << "Addr table avg reuse: " << (addr_reuse / 1024.0) << std::endl;
}

void PrintStats_Heartbeat() {
    // Optionally print streaming set count
    int streaming_sets = 0;
    for (uint32_t set = 0; set < LLC_SETS; ++set)
        if (stream_table[set].streaming) streaming_sets++;
    std::cout << "Streaming sets: " << streaming_sets << std::endl;
}