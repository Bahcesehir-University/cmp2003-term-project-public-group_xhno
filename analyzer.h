#pragma once

#include <string>
#include <vector>
#include <vector>
#include <cstdint>
#include <cstring>

/////////RESULT STRUCTURES
// Defined based on README requirements
struct ZoneCount {
    std::string zone;
    long long count;
};

struct SlotCount {
    std::string zone;
    int hour;
    long long count;
};

// //////// INTERNAL FAST MAP HELPER
struct ZoneEntry {
    std::string name;
    int id;
    uint64_t storedHash;
};

class FastZoneMap {
private:
    int* table;
    int tableSize;
    int tableMask;
    int threshold;

    std::vector<ZoneEntry> entries;

    void resize();

public:
    FastZoneMap();
    ~FastZoneMap();

    // Returns internal ID for a zone string
    int getId(const char* str, size_t len, uint64_t hash);

    const std::string& getName(int id) const;
    size_t size() const;
};

////// MAIN ANALYZER CLASS
class TripAnalyzer {
public:
    // Required Interface
    void ingestFile(const std::string& csvPath);
    std::vector<ZoneCount> topZones(int k = 10) const;
    std::vector<SlotCount> topBusySlots(int k = 10) const;

private:
    FastZoneMap zoneMap;
    std::vector<long long> zoneCountsInternal;
    std::vector<long long> slotCountsInternal;

    int expectedCommas = -1;

    // Internal helper to process a single line from the buffer
    void processRawLine(const char* start, const char* end);
};