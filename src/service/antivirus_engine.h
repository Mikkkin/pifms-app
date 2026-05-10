#pragma once

#include <cstdint>
#include <istream>
#include <map>
#include <string>
#include <utility>
#include <vector>

namespace pifms::service {

enum class ScanObjectType : std::uint8_t {
    Unknown = 0,
    Pe = 1,
    Script = 2,
    Com = 3
};

enum class ScanTargetType : std::uint8_t {
    File = 1,
    Directory = 2,
    FixedDrives = 3
};

struct AntivirusRecord {
    std::uint64_t objectSignaturePrefix = 0;
    std::uint32_t objectSignatureLength = 0;
    std::vector<std::uint8_t> objectSignature;
    std::uint64_t offsetBegin = 0;
    std::uint64_t offsetEnd = 0;
    ScanObjectType objectType = ScanObjectType::Unknown;
    std::vector<std::uint8_t> avRecordSignature;
    std::wstring threatName;
};

struct AntivirusDatabaseInfo {
    bool loaded = false;
    std::int64_t releaseUnixSeconds = 0;
    std::wstring releaseDate;
    std::uint32_t recordCount = 0;
};

struct ScanResult {
    std::wstring path;
    bool scanned = false;
    bool malicious = false;
    std::wstring threatName;
    ScanObjectType objectType = ScanObjectType::Unknown;
    std::uint64_t offset = 0;
    std::wstring error;
};

class AntivirusDatabase {
public:
    [[nodiscard]] bool LoadRawPackage(const std::vector<std::uint8_t>& packageData);
    [[nodiscard]] AntivirusDatabaseInfo GetInfo() const;
    [[nodiscard]] const std::map<std::uint64_t, std::vector<AntivirusRecord>>& RecordsByPrefix() const;
    [[nodiscard]] std::vector<std::pair<std::uint64_t, std::uint64_t>> FindPrefixMatches(
        const std::vector<std::uint8_t>& data
    ) const;
    [[nodiscard]] bool Empty() const;

private:
    struct AutomatonNode {
        std::map<std::uint8_t, std::size_t> next;
        std::size_t failure = 0;
        std::vector<std::uint64_t> prefixes;
    };

    void BuildAutomaton();

    AntivirusDatabaseInfo info_;
    std::map<std::uint64_t, std::vector<AntivirusRecord>> recordsByPrefix_;
    std::vector<AutomatonNode> automaton_;
};

class AntivirusEngine {
public:
    explicit AntivirusEngine(const AntivirusDatabase& database);

    [[nodiscard]] ScanResult ScanFile(const std::wstring& path) const;
    [[nodiscard]] ScanResult ScanStream(
        std::istream& input,
        const std::wstring& path,
        ScanObjectType objectType
    ) const;

private:
    const AntivirusDatabase& database_;
};

[[nodiscard]] ScanObjectType DetectObjectType(const std::wstring& path);
[[nodiscard]] std::wstring ScanObjectTypeName(ScanObjectType type);
[[nodiscard]] std::wstring FormatUnixSeconds(std::int64_t unixSeconds);

}
