#include "analyzer.h"
#include <fstream>
#include <iostream>
#include <algorithm>
#include <cstring>
#include <vector>

using namespace std;

// ==FAST MAP IMPLEMENTATION ==

FastZoneMap::FastZoneMap() {
    // Optimization: Start large to minimize resizing overhead
    tableSize = 2097152; // 2^21
    tableMask = tableSize - 1;
    threshold = (int)(tableSize * 0.5);

    table = new int[tableSize];
    std::memset(table, -1, sizeof(int) * tableSize);

    entries.reserve(50000);
}

FastZoneMap::~FastZoneMap() {
    delete[] table;
}

void FastZoneMap::resize() {
    long long newSize = (long long)tableSize * 2;
    if (newSize > 0x7FFFFFFF) return;

    int newSizeInt = (int)newSize;
    int newMask = newSizeInt - 1;

    int* newTable = new int[newSizeInt];
    std::memset(newTable, -1, sizeof(int) * newSizeInt);

    // Re-insert existing entries using STORED hash
    for (const auto& entry : entries) {
        int idx = entry.storedHash & newMask;

        while (newTable[idx] != -1) {
            idx = (idx + 1) & newMask;
        }
        newTable[idx] = entry.id;
    }

    delete[] table;
    table = newTable;
    tableSize = newSizeInt;
    tableMask = newMask;
    threshold = (int)(newSizeInt * 0.5);
}

int FastZoneMap::getId(const char* str, size_t len, uint64_t hash) {
    if ((int)entries.size() >= threshold) {
        resize();
    }

    int idx = hash & tableMask;

    while (table[idx] != -1) {
        int entryIdx = table[idx];
        const ZoneEntry& entry = entries[entryIdx];

        if (entry.storedHash == hash &&
            entry.name.length() == len &&
            std::memcmp(entry.name.data(), str, len) == 0) {
            return entry.id;
        }

        idx = (idx + 1) & tableMask;
    }

    int newId = (int)entries.size();
    entries.push_back({std::string(str, len), newId, hash});
    table[idx] = newId;
    return newId;
}

const std::string& FastZoneMap::getName(int id) const {
    return entries[id].name;
}

size_t FastZoneMap::size() const {
    return entries.size();
}

// == ANALYZER IMPLEMENTATION

void TripAnalyzer::processRawLine(const char* start, const char* end) {
    if (start >= end) return;

    int commaCount = 0;
    const char* c1 = nullptr;       // End of TripID
    const char* c2 = nullptr;       // End of PickupZone
    const char* spacePos = nullptr; // Start of Time
    const char* colonPos = nullptr; // Separator of Hour

    // FNV-1a Hash Constants
    uint64_t zoneHash = 14695981039346656037ULL;
    const uint64_t FNV_PRIME = 1099511628211ULL;

    for (const char* p = start; p < end; ++p) {
        char c = *p;

        if (c == ',') {
            commaCount++;
            if (commaCount == 1) {
                c1 = p;
            } else if (commaCount == 2) {
                c2 = p;
            }
        }
        else if (commaCount == 1) {
            // Compute hash on the fly
            zoneHash ^= (unsigned char)c;
            zoneHash *= FNV_PRIME;
        }
        else if (c == ' ') {
            if (commaCount >= 2 && !spacePos) {
                spacePos = p;
            }
        }
        else if (c == ':') {
            if (spacePos && !colonPos) {
                colonPos = p;
            }
        }
    }

    // Header detection logic:
    // If this is the first line, we determine the expected schema
    if (expectedCommas == -1) {
        expectedCommas = commaCount;
        return;
    }

    // Strict validation: must match header column count
    if (commaCount != expectedCommas) return;

    if (!c1 || !c2 || !spacePos || !colonPos) return;

    size_t zoneLen = c2 - (c1 + 1);
    if (zoneLen == 0) return;

    const char* hStart = spacePos + 1;
    size_t hLen = colonPos - hStart;
    int hour = -1;

    // Fast hour parsing
    if (hLen == 2) {
        unsigned char d1 = hStart[0] - '0';
        unsigned char d2 = hStart[1] - '0';
        if (d1 <= 9 && d2 <= 9) {
            hour = d1 * 10 + d2;
        }
    } else if (hLen == 1) {
        unsigned char d1 = hStart[0] - '0';
        if (d1 <= 9) {
            hour = d1;
        }
    }

    if (hour < 0 || hour > 23) return;

    // Aggregation
    int zId = zoneMap.getId(c1 + 1, zoneLen, zoneHash);

    // Dynamic array expansion
    if (zId >= (int)zoneCountsInternal.size()) {
        zoneCountsInternal.push_back(0);
        // Add 24 slots for the new zone
        slotCountsInternal.insert(slotCountsInternal.end(), 24, 0);
    }

    zoneCountsInternal[zId]++;
    slotCountsInternal[zId * 24 + hour]++;
}

void TripAnalyzer::ingestFile(const std::string& csvPath) {
    // Reset state in case ingestFile is called multiple times
    expectedCommas = -1;
    // Heuristic reservations
    if (zoneCountsInternal.empty()) {
        zoneCountsInternal.reserve(50000);
        slotCountsInternal.reserve(1200000);
    }

    std::ifstream file(csvPath, std::ios::binary);
    if (!file.is_open()) return;

    const size_t BUFFER_SIZE = 4 * 1024 * 1024; // 4MB Buffer
    std::vector<char> buffer(BUFFER_SIZE);

    size_t offset = 0;

    while (file) {
        file.read(buffer.data() + offset, BUFFER_SIZE - offset);
        std::streamsize bytesRead = file.gcount();

        if (bytesRead == 0) break;

        size_t totalBytes = offset + bytesRead;
        char* bufStart = buffer.data();
        char* bufEnd = bufStart + totalBytes;

        char* lineStart = bufStart;
        char* p = bufStart;

        while (p < bufEnd) {
            if (*p == '\n') {
                char* lineEnd = p;
                if (lineEnd > lineStart && *(lineEnd - 1) == '\r') {
                    lineEnd--;
                }

                if (lineEnd > lineStart) {
                    processRawLine(lineStart, lineEnd);
                }

                lineStart = p + 1;
            }
            p++;
        }

        // Move remaining partial line to front of buffer
        size_t remaining = bufEnd - lineStart;
        if (remaining > 0 && remaining < BUFFER_SIZE) {
            std::memmove(buffer.data(), lineStart, remaining);
        }

        offset = remaining;
    }

    // Process very last line if file doesn't end with \n
    if (offset > 0) {
        char* start = buffer.data();
        char* end = start + offset;
        if (end > start && *(end - 1) == '\r') end--;
        if (end > start) {
            processRawLine(start, end);
        }
    }
}

std::vector<ZoneCount> TripAnalyzer::topZones(int k) const {
    std::vector<ZoneCount> results;
    size_t numZones = zoneMap.size();
    results.reserve(numZones);

    for (size_t i = 0; i < numZones; ++i) {
        if (zoneCountsInternal[i] > 0) {
            results.push_back({zoneMap.getName(i), zoneCountsInternal[i]});
        }
    }

    // Deterministic Sort: Count Descending, then Zone Ascending
    std::sort(results.begin(), results.end(), [](const ZoneCount& a, const ZoneCount& b) {
        if (a.count != b.count) return a.count > b.count;
        return a.zone < b.zone;
    });

    if (k > 0 && results.size() > (size_t)k) {
        results.resize(k);
    }
    return results;
}

std::vector<SlotCount> TripAnalyzer::topBusySlots(int k) const {
    std::vector<SlotCount> results;
    size_t numZones = zoneMap.size();

    // Flatten the internal 1D array into result structs
    for (size_t z = 0; z < numZones; ++z) {
        for (int h = 0; h < 24; ++h) {
            size_t idx = z * 24 + h;
            if (idx < slotCountsInternal.size()) {
                long long count = slotCountsInternal[idx];
                if (count > 0) {
                    results.push_back({zoneMap.getName(z), h, count});
                }
            }
        }
    }

    // Deterministic Sort: Count Desc -> Zone Asc -> Hour Asc
    std::sort(results.begin(), results.end(), [](const SlotCount& a, const SlotCount& b) {
        if (a.count != b.count) return a.count > b.count;
        if (a.zone != b.zone) return a.zone < b.zone;
        return a.hour < b.hour;
    });

    if (k > 0 && results.size() > (size_t)k) {
        results.resize(k);
    }
    return results;
}