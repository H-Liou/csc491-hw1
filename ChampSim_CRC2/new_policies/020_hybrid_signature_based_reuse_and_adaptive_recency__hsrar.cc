#include <vector>
#include <cstdint>
#include <iostream>
#include <algorithm>
#include <unordered_map>
#include "../inc/champsim_crc2.h"

#define NUM_CORE 1
#define LLC_SETS (NUM_CORE * 2048)
#define LLC_WAYS 16

constexpr int SIGNATURE_TABLE_SIZE = 1024; // Global signature table size
constexpr int SIGNATURE_COUNTER_MAX = 7;
constexpr int SIGNATURE_COUNTER_MIN = 0;
constexpr int SIGNATURE_PROMOTE_THRESHOLD = 2; // Reuse prediction threshold

// Per-line state
struct LineState {
    uint64_t tag;
    uint8_t valid;
    uint8_t lru_position;
    uint16_t signature; // compact signature
    uint8_t predicted_reuse; // predicted reuse (counter)
};

// Per-set state
struct SetState {
    int access_count;
    int recent_hits;
    int recent_misses;
    int spatial_hits;
    uint64_t last_addr;
    int spatial_stride;
};

std::vector<std::vector<LineState>> line_states;
std::vector<SetState> set_states;

// Global signature table: signature -> reuse counter
std::unordered_map<uint16_t, uint8_t> signature_table;

// Stats
uint64_t total_evictions = 0;
uint64_t reuse_evictions = 0;
uint64_t lru_evictions = 0;
uint64_t signature_promotions = 0;
uint64_t spatial_promotions = 0;

// Generate a compact signature from PC and address
inline uint16_t get_signature(uint64_t PC, uint64_t paddr) {
    // Use lower bits of PC and block address for signature
    return ((PC & 0x3FF) ^ ((paddr >> 6) & 0x3FF)) & 0x3FF;
}

void InitReplacementState() {
    line_states.resize(LLC_SETS, std::vector<LineState>(LLC_WAYS));
    set_states.resize(LLC_SETS);
    signature_table.clear();

    for (uint32_t set = 0; set < LLC_SETS; ++set) {
        for (uint32_t way = 0; way < LLC_WAYS; ++way) {
            line_states[set][way].tag = 0;
            line_states[set][way].valid = 0;
            line_states[set][way].lru_position = way;
            line_states[set][way].signature = 0;
            line_states[set][way].predicted_reuse = 0;
        }
        set_states[set].access_count = 0;
        set_states[set].recent_hits = 0;
        set_states[set].recent_misses = 0;
        set_states[set].spatial_hits = 0;
        set_states[set].last_addr = 0;
        set_states[set].spatial_stride = 0;
    }
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
    auto& lstates = line_states[set];

    // Prefer invalid block
    for (int way = 0; way < LLC_WAYS; ++way)
        if (!lstates[way].valid)
            return way;

    // Step 1: Find block with lowest predicted reuse (signature counter)
    int victim = -1;
    uint8_t min_reuse = SIGNATURE_COUNTER_MAX + 1;
    int lru_pos = -1;

    for (int way = 0; way < LLC_WAYS; ++way) {
        uint8_t reuse = lstates[way].predicted_reuse;
        if (reuse < min_reuse) {
            min_reuse = reuse;
            victim = way;
            lru_pos = lstates[way].lru_position;
        }
        // If multiple blocks have min reuse, pick LRU among them
        else if (reuse == min_reuse && lstates[way].lru_position > lru_pos) {
            victim = way;
            lru_pos = lstates[way].lru_position;
        }
    }

    if (victim != -1 && min_reuse <= SIGNATURE_PROMOTE_THRESHOLD) {
        reuse_evictions++;
        total_evictions++;
        return victim;
    }

    // Step 2: Fallback to LRU if all predicted reuse are high
    lru_pos = -1;
    for (int way = 0; way < LLC_WAYS; ++way) {
        if (lstates[way].lru_position > lru_pos) {
            lru_pos = lstates[way].lru_position;
            victim = way;
        }
    }
    lru_evictions++;
    total_evictions++;
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
    auto& lstates = line_states[set];
    auto& sstate = set_states[set];

    // --- Signature update ---
    uint16_t sig = get_signature(PC, paddr);
    uint8_t& sig_counter = signature_table[sig];
    if (hit) {
        if (sig_counter < SIGNATURE_COUNTER_MAX)
            sig_counter++;
    } else {
        if (sig_counter > SIGNATURE_COUNTER_MIN)
            sig_counter--;
    }

    lstates[way].signature = sig;
    lstates[way].predicted_reuse = sig_counter;

    // --- LRU stack update ---
    uint8_t old_pos = lstates[way].lru_position;
    for (int i = 0; i < LLC_WAYS; ++i) {
        if (lstates[i].lru_position < old_pos)
            lstates[i].lru_position++;
    }
    lstates[way].lru_position = 0;

    // --- Spatial locality detection ---
    if (sstate.last_addr != 0) {
        int stride = static_cast<int>(paddr - sstate.last_addr);
        if (stride == sstate.spatial_stride && stride != 0) {
            sstate.spatial_hits++;
            // If spatial hits are frequent, promote block reuse prediction
            if (lstates[way].predicted_reuse < SIGNATURE_COUNTER_MAX)
                lstates[way].predicted_reuse++;
            spatial_promotions++;
        }
        sstate.spatial_stride = stride;
    }
    sstate.last_addr = paddr;

    // --- Stats ---
    sstate.access_count++;
    if (hit)
        sstate.recent_hits++;
    else
        sstate.recent_misses++;

    lstates[way].tag = paddr;
    lstates[way].valid = 1;
}

void PrintStats() {
    std::cout << "HSRAR: Total evictions: " << total_evictions << std::endl;
    std::cout << "HSRAR: Reuse-based evictions: " << reuse_evictions << std::endl;
    std::cout << "HSRAR: LRU evictions: " << lru_evictions << std::endl;
    std::cout << "HSRAR: Signature promotions: " << signature_promotions << std::endl;
    std::cout << "HSRAR: Spatial promotions: " << spatial_promotions << std::endl;
}

void PrintStats_Heartbeat() {
    std::cout << "HSRAR heartbeat: evictions=" << total_evictions
              << " reuse_evictions=" << reuse_evictions
              << " lru_evictions=" << lru_evictions
              << " signature_promotions=" << signature_promotions
              << " spatial_promotions=" << spatial_promotions << std::endl;
}