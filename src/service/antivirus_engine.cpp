#include "service/antivirus_engine.h"

#include "common/text_utils.h"

#include <windows.h>
#include <wincrypt.h>

#include <algorithm>
#include <array>
#include <cwctype>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <queue>

namespace {

constexpr std::uint8_t kManifestMagic[] = {
    'M', 'F', '-', 'K', 'h', 'a', 'n', 'g', 'i', 'l', 'd', 'i', 'n'
};
constexpr std::uint8_t kDataMagic[] = {
    'D', 'B', '-', 'K', 'h', 'a', 'n', 'g', 'i', 'l', 'd', 'i', 'n'
};
constexpr std::uint16_t kBinaryVersion = 1;
constexpr std::uint32_t kSha256Length = 32;
constexpr std::uint32_t kPrefixLength = 8;

class BinaryReader {
public:
    explicit BinaryReader(const std::vector<std::uint8_t>& data)
        : data_(data)
    {
    }

    explicit BinaryReader(const std::vector<std::uint8_t>& data, std::size_t offset)
        : data_(data),
          position_(offset)
    {
    }

    [[nodiscard]] bool ReadUInt8(std::uint8_t& value)
    {
        if (Remaining() < 1) {
            return false;
        }
        value = data_[position_++];
        return true;
    }

    [[nodiscard]] bool ReadUInt16(std::uint16_t& value)
    {
        if (Remaining() < 2) {
            return false;
        }
        value = static_cast<std::uint16_t>((data_[position_] << 8) | data_[position_ + 1]);
        position_ += 2;
        return true;
    }

    [[nodiscard]] bool ReadUInt32(std::uint32_t& value)
    {
        if (Remaining() < 4) {
            return false;
        }
        value =
            (static_cast<std::uint32_t>(data_[position_]) << 24) |
            (static_cast<std::uint32_t>(data_[position_ + 1]) << 16) |
            (static_cast<std::uint32_t>(data_[position_ + 2]) << 8) |
            static_cast<std::uint32_t>(data_[position_ + 3]);
        position_ += 4;
        return true;
    }

    [[nodiscard]] bool ReadUInt64(std::uint64_t& value)
    {
        if (Remaining() < 8) {
            return false;
        }
        value = 0;
        for (int index = 0; index < 8; ++index) {
            value = (value << 8) | data_[position_ + index];
        }
        position_ += 8;
        return true;
    }

    [[nodiscard]] bool ReadBytes(std::size_t length, std::vector<std::uint8_t>& value)
    {
        if (Remaining() < length) {
            return false;
        }
        value.assign(data_.begin() + static_cast<std::ptrdiff_t>(position_),
            data_.begin() + static_cast<std::ptrdiff_t>(position_ + length));
        position_ += length;
        return true;
    }

    [[nodiscard]] bool ReadByteArray(std::vector<std::uint8_t>& value)
    {
        std::uint32_t length = 0;
        return ReadUInt32(length) && ReadBytes(length, value);
    }

    [[nodiscard]] bool ReadString(std::wstring& value)
    {
        std::vector<std::uint8_t> bytes;
        if (!ReadByteArray(bytes)) {
            return false;
        }
        value = pifms::Utf8ToWide(std::string(bytes.begin(), bytes.end()));
        return true;
    }

    [[nodiscard]] bool Skip(std::size_t length)
    {
        if (Remaining() < length) {
            return false;
        }
        position_ += length;
        return true;
    }

    [[nodiscard]] bool AtEnd() const noexcept
    {
        return position_ == data_.size();
    }

    [[nodiscard]] std::size_t Position() const noexcept
    {
        return position_;
    }

    [[nodiscard]] std::size_t Remaining() const noexcept
    {
        return position_ <= data_.size() ? data_.size() - position_ : 0;
    }

private:
    const std::vector<std::uint8_t>& data_;
    std::size_t position_ = 0;
};

struct ManifestEntry {
    std::uint8_t status = 0;
    std::uint64_t recordOffset = 0;
    std::uint32_t recordLength = 0;
    std::vector<std::uint8_t> recordSignature;
};

[[nodiscard]] bool ReadMagic(BinaryReader& reader, const std::uint8_t* magic, std::size_t size)
{
    std::vector<std::uint8_t> value;
    return reader.ReadBytes(size, value) && std::equal(value.begin(), value.end(), magic);
}

[[nodiscard]] bool ReadPackagePart(BinaryReader& reader, std::vector<std::uint8_t>& value)
{
    std::uint32_t length = 0;
    return reader.ReadUInt32(length) && reader.ReadBytes(length, value);
}

[[nodiscard]] std::uint64_t PrefixToUInt64(const std::vector<std::uint8_t>& prefix)
{
    std::uint64_t value = 0;
    for (std::uint8_t byte : prefix) {
        value = (value << 8) | byte;
    }
    return value;
}

[[nodiscard]] bool Sha256(const std::vector<std::uint8_t>& data, std::vector<std::uint8_t>& hash)
{
    HCRYPTPROV provider = 0;
    HCRYPTHASH hashHandle = 0;
    const BOOL hasProvider = CryptAcquireContextW(
        &provider,
        nullptr,
        nullptr,
        PROV_RSA_AES,
        CRYPT_VERIFYCONTEXT
    );
    if (!hasProvider) {
        return false;
    }

    bool ok = false;
    if (CryptCreateHash(provider, CALG_SHA_256, 0, 0, &hashHandle)) {
        if (data.empty() || CryptHashData(hashHandle, data.data(), static_cast<DWORD>(data.size()), 0)) {
            DWORD hashLength = kSha256Length;
            hash.assign(hashLength, 0);
            ok = CryptGetHashParam(hashHandle, HP_HASHVAL, hash.data(), &hashLength, 0) == TRUE;
            hash.resize(hashLength);
        }
        CryptDestroyHash(hashHandle);
    }

    CryptReleaseContext(provider, 0);
    return ok;
}

[[nodiscard]] std::wstring LowerExtension(const std::wstring& path)
{
    std::wstring extension = std::filesystem::path(path).extension().wstring();
    std::transform(extension.begin(), extension.end(), extension.begin(), [](wchar_t value) {
        return static_cast<wchar_t>(std::towlower(value));
    });
    return extension;
}

[[nodiscard]] bool HasMzHeader(const std::wstring& path)
{
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        return false;
    }

    char magic[2] = {};
    file.read(magic, sizeof(magic));
    return file.gcount() == sizeof(magic) && magic[0] == 'M' && magic[1] == 'Z';
}

[[nodiscard]] bool ParseManifest(
    const std::vector<std::uint8_t>& manifest,
    std::int64_t& releaseUnixSeconds,
    std::vector<ManifestEntry>& entries
)
{
    BinaryReader reader(manifest);
    std::uint16_t version = 0;
    std::uint8_t exportType = 0;
    std::uint64_t generatedAtMillis = 0;
    std::uint64_t sinceMillis = 0;
    std::uint32_t recordCount = 0;

    if (!ReadMagic(reader, kManifestMagic, sizeof(kManifestMagic)) ||
        !reader.ReadUInt16(version) ||
        version != kBinaryVersion ||
        !reader.ReadUInt8(exportType) ||
        !reader.ReadUInt64(generatedAtMillis) ||
        !reader.ReadUInt64(sinceMillis) ||
        !reader.ReadUInt32(recordCount)) {
        return false;
    }
    static_cast<void>(exportType);
    static_cast<void>(sinceMillis);

    std::vector<std::uint8_t> dataHash;
    if (!reader.ReadBytes(kSha256Length, dataHash)) {
        return false;
    }

    entries.clear();
    entries.reserve(recordCount);
    for (std::uint32_t index = 0; index < recordCount; ++index) {
        ManifestEntry entry;
        if (!reader.Skip(16) ||
            !reader.ReadUInt8(entry.status) ||
            !reader.Skip(8) ||
            !reader.ReadUInt64(entry.recordOffset) ||
            !reader.ReadUInt32(entry.recordLength) ||
            !reader.ReadByteArray(entry.recordSignature)) {
            return false;
        }
        entries.push_back(std::move(entry));
    }

    std::vector<std::uint8_t> manifestSignature;
    if (!reader.ReadByteArray(manifestSignature) || !reader.AtEnd()) {
        return false;
    }

    releaseUnixSeconds = static_cast<std::int64_t>(generatedAtMillis / 1000);
    return true;
}

[[nodiscard]] bool ParseRecord(
    const std::vector<std::uint8_t>& data,
    std::size_t payloadOffset,
    const ManifestEntry& entry,
    pifms::service::AntivirusRecord& record
)
{
    if (entry.status != 1 || entry.recordOffset > data.size() || payloadOffset > data.size()) {
        return false;
    }

    const std::size_t offset = payloadOffset + static_cast<std::size_t>(entry.recordOffset);
    if (entry.recordLength > data.size() - offset) {
        return false;
    }

    BinaryReader reader(data, offset);
    std::wstring fileType;
    std::vector<std::uint8_t> prefix;
    std::uint64_t remainderLength = 0;
    if (!reader.ReadString(record.threatName) ||
        !reader.ReadByteArray(prefix) ||
        prefix.size() != kPrefixLength ||
        !reader.ReadByteArray(record.objectSignature) ||
        !reader.ReadUInt64(remainderLength) ||
        !reader.ReadString(fileType) ||
        !reader.ReadUInt64(record.offsetBegin) ||
        !reader.ReadUInt64(record.offsetEnd)) {
        return false;
    }

    if (reader.Position() != offset + entry.recordLength || remainderLength > UINT32_MAX - kPrefixLength) {
        return false;
    }

    std::wstring lowerType = fileType;
    std::transform(lowerType.begin(), lowerType.end(), lowerType.begin(), [](wchar_t value) {
        return static_cast<wchar_t>(std::towlower(value));
    });

    if (lowerType == L"exe" || lowerType == L"dll" || lowerType == L"pe" ||
        lowerType == L"application/x-msdownload" || lowerType == L"application/vnd.microsoft.portable-executable") {
        record.objectType = pifms::service::ScanObjectType::Pe;
    } else if (lowerType == L"com" || lowerType == L"dos-com" || lowerType == L"application/x-msdos-program") {
        record.objectType = pifms::service::ScanObjectType::Com;
    } else if (lowerType == L"script" || lowerType == L"js" || lowerType == L"py" || lowerType == L"ps1" ||
               lowerType == L"javascript" || lowerType == L"python" || lowerType == L"powershell" ||
               lowerType == L"text/javascript" || lowerType == L"text/x-python") {
        record.objectType = pifms::service::ScanObjectType::Script;
    } else {
        return false;
    }

    record.objectSignaturePrefix = PrefixToUInt64(prefix);
    record.objectSignatureLength = static_cast<std::uint32_t>(kPrefixLength + remainderLength);
    record.avRecordSignature = entry.recordSignature;
    return true;
}

}

namespace pifms::service {

[[nodiscard]] bool AntivirusDatabase::LoadRawPackage(const std::vector<std::uint8_t>& packageData)
{
    BinaryReader packageReader(packageData);
    std::vector<std::uint8_t> manifest;
    std::vector<std::uint8_t> data;
    if (!ReadPackagePart(packageReader, manifest) ||
        !ReadPackagePart(packageReader, data) ||
        !packageReader.AtEnd()) {
        return false;
    }

    std::int64_t releaseUnixSeconds = 0;
    std::vector<ManifestEntry> entries;
    if (!ParseManifest(manifest, releaseUnixSeconds, entries)) {
        return false;
    }

    BinaryReader dataHeader(data);
    std::uint16_t version = 0;
    std::uint32_t recordCount = 0;
    if (!ReadMagic(dataHeader, kDataMagic, sizeof(kDataMagic)) ||
        !dataHeader.ReadUInt16(version) ||
        version != kBinaryVersion ||
        !dataHeader.ReadUInt32(recordCount) ||
        recordCount != entries.size()) {
        return false;
    }
    const std::size_t payloadOffset = dataHeader.Position();

    std::map<std::uint64_t, std::vector<AntivirusRecord>> records;
    for (const ManifestEntry& entry : entries) {
        AntivirusRecord record;
        if (ParseRecord(data, payloadOffset, entry, record)) {
            records[record.objectSignaturePrefix].push_back(std::move(record));
        }
    }

    AntivirusDatabaseInfo nextInfo;
    nextInfo.loaded = true;
    nextInfo.releaseUnixSeconds = releaseUnixSeconds;
    nextInfo.releaseDate = FormatUnixSeconds(releaseUnixSeconds);
    nextInfo.recordCount = 0;
    for (const auto& pair : records) {
        nextInfo.recordCount += static_cast<std::uint32_t>(pair.second.size());
    }

    info_ = std::move(nextInfo);
    recordsByPrefix_ = std::move(records);
    BuildAutomaton();
    return true;
}

[[nodiscard]] AntivirusDatabaseInfo AntivirusDatabase::GetInfo() const
{
    return info_;
}

[[nodiscard]] const std::map<std::uint64_t, std::vector<AntivirusRecord>>& AntivirusDatabase::RecordsByPrefix() const
{
    return recordsByPrefix_;
}

[[nodiscard]] std::vector<std::pair<std::uint64_t, std::uint64_t>> AntivirusDatabase::FindPrefixMatches(
    const std::vector<std::uint8_t>& data
) const
{
    std::vector<std::pair<std::uint64_t, std::uint64_t>> matches;
    if (automaton_.empty()) {
        return matches;
    }

    std::size_t node = 0;
    for (std::size_t index = 0; index < data.size(); ++index) {
        const std::uint8_t byte = data[index];
        while (node != 0 && automaton_[node].next.find(byte) == automaton_[node].next.end()) {
            node = automaton_[node].failure;
        }

        const auto next = automaton_[node].next.find(byte);
        node = next == automaton_[node].next.end() ? 0 : next->second;

        if (index + 1 < kPrefixLength) {
            continue;
        }

        const std::uint64_t position = static_cast<std::uint64_t>(index + 1 - kPrefixLength);
        for (std::uint64_t prefix : automaton_[node].prefixes) {
            matches.emplace_back(position, prefix);
        }
    }
    return matches;
}

[[nodiscard]] bool AntivirusDatabase::Empty() const
{
    return recordsByPrefix_.empty();
}

void AntivirusDatabase::BuildAutomaton()
{
    automaton_.clear();
    automaton_.push_back({});

    for (const auto& pair : recordsByPrefix_) {
        std::array<std::uint8_t, kPrefixLength> bytes = {};
        std::uint64_t value = pair.first;
        for (std::size_t index = 0; index < bytes.size(); ++index) {
            bytes[bytes.size() - index - 1] = static_cast<std::uint8_t>(value & 0xFF);
            value >>= 8;
        }

        std::size_t node = 0;
        for (std::uint8_t byte : bytes) {
            auto next = automaton_[node].next.find(byte);
            if (next == automaton_[node].next.end()) {
                automaton_[node].next[byte] = automaton_.size();
                automaton_.push_back({});
                node = automaton_.size() - 1;
            } else {
                node = next->second;
            }
        }
        automaton_[node].prefixes.push_back(pair.first);
    }

    std::queue<std::size_t> pending;
    for (const auto& edge : automaton_[0].next) {
        pending.push(edge.second);
    }

    while (!pending.empty()) {
        const std::size_t current = pending.front();
        pending.pop();

        for (const auto& edge : automaton_[current].next) {
            std::size_t failure = automaton_[current].failure;
            while (failure != 0 && automaton_[failure].next.find(edge.first) == automaton_[failure].next.end()) {
                failure = automaton_[failure].failure;
            }

            auto next = automaton_[failure].next.find(edge.first);
            if (next != automaton_[failure].next.end()) {
                automaton_[edge.second].failure = next->second;
            }

            const auto& inherited = automaton_[automaton_[edge.second].failure].prefixes;
            automaton_[edge.second].prefixes.insert(
                automaton_[edge.second].prefixes.end(),
                inherited.begin(),
                inherited.end()
            );
            pending.push(edge.second);
        }
    }
}

AntivirusEngine::AntivirusEngine(const AntivirusDatabase& database)
    : database_(database)
{
}

[[nodiscard]] ScanResult AntivirusEngine::ScanFile(const std::wstring& path) const
{
    ScanResult result;
    result.path = path;
    result.objectType = DetectObjectType(path);

    std::ifstream file(path, std::ios::binary);
    if (!file) {
        result.error = L"Не удалось открыть файл";
        return result;
    }

    return ScanStream(file, path, result.objectType);
}

[[nodiscard]] ScanResult AntivirusEngine::ScanStream(
    std::istream& input,
    const std::wstring& path,
    ScanObjectType objectType
) const
{
    ScanResult result;
    result.path = path;
    result.objectType = objectType;
    result.scanned = true;

    std::vector<std::uint8_t> content(
        (std::istreambuf_iterator<char>(input)),
        std::istreambuf_iterator<char>()
    );
    if (content.size() < kPrefixLength || database_.Empty()) {
        return result;
    }

    for (const auto& match : database_.FindPrefixMatches(content)) {
        const std::uint64_t position = match.first;
        const std::uint64_t prefix = match.second;
        const auto found = database_.RecordsByPrefix().find(prefix);
        if (found == database_.RecordsByPrefix().end()) {
            continue;
        }

        for (const AntivirusRecord& record : found->second) {
            if (record.objectType != objectType) {
                continue;
            }
            if (position < record.offsetBegin || position > record.offsetEnd) {
                continue;
            }
            if (record.objectSignatureLength < kPrefixLength ||
                position + record.objectSignatureLength > content.size()) {
                continue;
            }

            std::vector<std::uint8_t> fragment(
                content.begin() + static_cast<std::ptrdiff_t>(position),
                content.begin() + static_cast<std::ptrdiff_t>(position + record.objectSignatureLength)
            );
            std::vector<std::uint8_t> hash;
            if (!Sha256(fragment, hash)) {
                result.error = L"Не удалось вычислить хэш";
                return result;
            }
            if (hash == record.objectSignature) {
                result.malicious = true;
                result.threatName = record.threatName;
                result.offset = static_cast<std::uint64_t>(position);
                return result;
            }
        }
    }

    return result;
}

[[nodiscard]] ScanObjectType DetectObjectType(const std::wstring& path)
{
    if (HasMzHeader(path)) {
        return ScanObjectType::Pe;
    }

    const std::wstring extension = LowerExtension(path);
    if (extension == L".exe" || extension == L".dll" || extension == L".sys") {
        return ScanObjectType::Pe;
    }
    if (extension == L".com") {
        return ScanObjectType::Com;
    }
    if (extension == L".js" || extension == L".py" || extension == L".ps1" ||
        extension == L".vbs" || extension == L".bat" || extension == L".cmd") {
        return ScanObjectType::Script;
    }
    return ScanObjectType::Unknown;
}

[[nodiscard]] std::wstring ScanObjectTypeName(ScanObjectType type)
{
    switch (type) {
    case ScanObjectType::Pe:
        return L"PE";
    case ScanObjectType::Script:
        return L"Script";
    case ScanObjectType::Com:
        return L"COM";
    default:
        return L"Unknown";
    }
}

[[nodiscard]] std::wstring FormatUnixSeconds(std::int64_t unixSeconds)
{
    if (unixSeconds <= 0) {
        return {};
    }

    std::time_t value = static_cast<std::time_t>(unixSeconds);
    std::tm timeValue = {};
    if (gmtime_s(&timeValue, &value) != 0) {
        return {};
    }

    wchar_t buffer[32] = {};
    if (wcsftime(buffer, ARRAYSIZE(buffer), L"%Y-%m-%d %H:%M:%S UTC", &timeValue) == 0) {
        return {};
    }
    return buffer;
}

}
