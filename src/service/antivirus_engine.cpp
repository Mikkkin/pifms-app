#include "service/antivirus_engine.h"

#include "common/text_utils.h"

#include <windows.h>
#include <wincrypt.h>

#include <algorithm>
#include <array>
#include <cctype>
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
        std::string text;
        if (!ReadUtf8String(text)) {
            return false;
        }
        value = pifms::Utf8ToWide(text);
        return true;
    }

    [[nodiscard]] bool ReadUtf8String(std::string& value)
    {
        std::vector<std::uint8_t> bytes;
        if (!ReadByteArray(bytes)) {
            return false;
        }
        value.assign(bytes.begin(), bytes.end());
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
    std::string id;
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

[[nodiscard]] std::string HexLower(const std::vector<std::uint8_t>& data)
{
    constexpr char digits[] = "0123456789abcdef";
    std::string result;
    result.reserve(data.size() * 2);
    for (std::uint8_t byte : data) {
        result.push_back(digits[(byte >> 4) & 0x0F]);
        result.push_back(digits[byte & 0x0F]);
    }
    return result;
}

[[nodiscard]] std::string HexUpper(const std::vector<std::uint8_t>& data)
{
    constexpr char digits[] = "0123456789ABCDEF";
    std::string result;
    result.reserve(data.size() * 2);
    for (std::uint8_t byte : data) {
        result.push_back(digits[(byte >> 4) & 0x0F]);
        result.push_back(digits[byte & 0x0F]);
    }
    return result;
}

[[nodiscard]] std::string UuidToString(const std::vector<std::uint8_t>& bytes)
{
    if (bytes.size() != 16) {
        return {};
    }

    const std::string hex = HexLower(bytes);
    return hex.substr(0, 8) + "-" + hex.substr(8, 4) + "-" + hex.substr(12, 4) + "-" +
        hex.substr(16, 4) + "-" + hex.substr(20, 12);
}

void AppendJsonString(std::string& output, const std::string& value)
{
    output.push_back('"');
    for (unsigned char ch : value) {
        switch (ch) {
        case '"':
            output += "\\\"";
            break;
        case '\\':
            output += "\\\\";
            break;
        case '\b':
            output += "\\b";
            break;
        case '\f':
            output += "\\f";
            break;
        case '\n':
            output += "\\n";
            break;
        case '\r':
            output += "\\r";
            break;
        case '\t':
            output += "\\t";
            break;
        default:
            if (ch <= 0x1F) {
                constexpr char digits[] = "0123456789abcdef";
                output += "\\u00";
                output.push_back(digits[(ch >> 4) & 0x0F]);
                output.push_back(digits[ch & 0x0F]);
            } else {
                output.push_back(static_cast<char>(ch));
            }
            break;
        }
    }
    output.push_back('"');
}

[[nodiscard]] std::vector<std::uint8_t> BytesFromString(const std::string& value)
{
    return std::vector<std::uint8_t>(value.begin(), value.end());
}

[[nodiscard]] std::string BuildRecordSigningPayload(const pifms::service::AntivirusRecord& record)
{
    std::string payload;
    payload += "{\"fileType\":";
    AppendJsonString(payload, record.fileTypeUtf8);
    payload += ",\"firstBytesHex\":";
    AppendJsonString(payload, record.firstBytesHex);
    payload += ",\"offsetEnd\":";
    payload += std::to_string(record.offsetEnd);
    payload += ",\"offsetStart\":";
    payload += std::to_string(record.offsetBegin);
    payload += ",\"remainderHashHex\":";
    AppendJsonString(payload, record.remainderHashHex);
    payload += ",\"remainderLength\":";
    payload += std::to_string(record.remainderLength);
    payload += ",\"status\":\"ACTUAL\",\"threatName\":";
    AppendJsonString(payload, pifms::WideToUtf8(record.threatName));
    payload += "}";
    return payload;
}

[[nodiscard]] bool ReadFileBytes(const std::wstring& path, std::vector<std::uint8_t>& bytes)
{
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        return false;
    }

    bytes.assign(std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>());
    return !bytes.empty();
}

[[nodiscard]] bool DecodeCertificate(const std::vector<std::uint8_t>& encoded, std::vector<std::uint8_t>& der)
{
    if (encoded.empty()) {
        return false;
    }

    DWORD derLength = 0;
    const std::string text(encoded.begin(), encoded.end());
    if (CryptStringToBinaryA(
            text.c_str(),
            static_cast<DWORD>(text.size()),
            CRYPT_STRING_BASE64HEADER,
            nullptr,
            &derLength,
            nullptr,
            nullptr)) {
        der.assign(derLength, 0);
        return CryptStringToBinaryA(
            text.c_str(),
            static_cast<DWORD>(text.size()),
            CRYPT_STRING_BASE64HEADER,
            der.data(),
            &derLength,
            nullptr,
            nullptr) == TRUE;
    }

    der = encoded;
    return true;
}

[[nodiscard]] bool VerifySignature(
    const std::vector<std::uint8_t>& payload,
    const std::vector<std::uint8_t>& signature,
    const std::wstring& certificatePath
)
{
    if (payload.empty() || signature.empty() || certificatePath.empty()) {
        return false;
    }

    std::vector<std::uint8_t> encodedCertificate;
    std::vector<std::uint8_t> derCertificate;
    if (!ReadFileBytes(certificatePath, encodedCertificate) ||
        !DecodeCertificate(encodedCertificate, derCertificate)) {
        return false;
    }

    PCCERT_CONTEXT certificate = CertCreateCertificateContext(
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        derCertificate.data(),
        static_cast<DWORD>(derCertificate.size())
    );
    if (certificate == nullptr) {
        return false;
    }

    HCRYPTPROV provider = 0;
    HCRYPTKEY publicKey = 0;
    HCRYPTHASH hash = 0;
    bool ok = false;

    if (CryptAcquireContextW(&provider, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT) &&
        CryptImportPublicKeyInfo(
            provider,
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            &certificate->pCertInfo->SubjectPublicKeyInfo,
            &publicKey) &&
        CryptCreateHash(provider, CALG_SHA_256, 0, 0, &hash) &&
        CryptHashData(hash, payload.data(), static_cast<DWORD>(payload.size()), 0)) {
        std::vector<std::uint8_t> nativeSignature(signature.rbegin(), signature.rend());
        ok = CryptVerifySignatureW(
            hash,
            nativeSignature.data(),
            static_cast<DWORD>(nativeSignature.size()),
            publicKey,
            nullptr,
            0) == TRUE;
    }

    if (hash != 0) {
        CryptDestroyHash(hash);
    }
    if (publicKey != 0) {
        CryptDestroyKey(publicKey);
    }
    if (provider != 0) {
        CryptReleaseContext(provider, 0);
    }
    CertFreeCertificateContext(certificate);
    return ok;
}

[[nodiscard]] bool VerifySignatureAnyCertificate(
    const std::vector<std::uint8_t>& payload,
    const std::vector<std::uint8_t>& signature,
    const std::wstring& certificatePath
)
{
    if (VerifySignature(payload, signature, certificatePath)) {
        return true;
    }

    std::filesystem::path path(certificatePath);
    path.replace_filename(L"dmitrysigning.crt");
    return VerifySignature(payload, signature, path.wstring());
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
    std::vector<std::uint8_t>& dataHash,
    std::vector<std::uint8_t>& unsignedManifest,
    std::vector<std::uint8_t>& manifestSignature,
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

    if (!reader.ReadBytes(kSha256Length, dataHash)) {
        return false;
    }

    entries.clear();
    entries.reserve(recordCount);
    for (std::uint32_t index = 0; index < recordCount; ++index) {
        ManifestEntry entry;
        std::vector<std::uint8_t> idBytes;
        if (!reader.ReadBytes(16, idBytes) ||
            !reader.ReadUInt8(entry.status) ||
            !reader.Skip(8) ||
            !reader.ReadUInt64(entry.recordOffset) ||
            !reader.ReadUInt32(entry.recordLength) ||
            !reader.ReadByteArray(entry.recordSignature)) {
            return false;
        }
        entry.id = UuidToString(idBytes);
        entries.push_back(std::move(entry));
    }

    const std::size_t unsignedEnd = reader.Position();
    if (!reader.ReadByteArray(manifestSignature) || !reader.AtEnd()) {
        return false;
    }

    unsignedManifest.assign(manifest.begin(), manifest.begin() + static_cast<std::ptrdiff_t>(unsignedEnd));
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
    std::vector<std::uint8_t> prefix;
    if (!reader.ReadString(record.threatName) ||
        !reader.ReadByteArray(prefix) ||
        prefix.size() != kPrefixLength ||
        !reader.ReadByteArray(record.objectSignature) ||
        !reader.ReadUInt64(record.remainderLength) ||
        !reader.ReadUtf8String(record.fileTypeUtf8) ||
        !reader.ReadUInt64(record.offsetBegin) ||
        !reader.ReadUInt64(record.offsetEnd)) {
        return false;
    }

    if (reader.Position() != offset + entry.recordLength || record.remainderLength > UINT32_MAX - kPrefixLength) {
        return false;
    }

    std::string lowerType = record.fileTypeUtf8;
    std::transform(lowerType.begin(), lowerType.end(), lowerType.begin(), [](unsigned char value) {
        return static_cast<char>(std::tolower(value));
    });

    if (lowerType == "exe" || lowerType == "dll" || lowerType == "pe" ||
        lowerType == "application/x-msdownload" || lowerType == "application/vnd.microsoft.portable-executable") {
        record.objectType = pifms::service::ScanObjectType::Pe;
    } else if (lowerType == "com" || lowerType == "dos-com" || lowerType == "application/x-msdos-program") {
        record.objectType = pifms::service::ScanObjectType::Com;
    } else if (lowerType == "script" || lowerType == "js" || lowerType == "py" || lowerType == "ps1" ||
               lowerType == "javascript" || lowerType == "python" || lowerType == "powershell" ||
               lowerType == "text/javascript" || lowerType == "text/x-python" ||
               lowerType == "docx" ||
               lowerType == "application/octet-stream" ||
               lowerType == "application/vnd.openxmlformats-officedocument.wordprocessingml.document") {
        record.objectType = pifms::service::ScanObjectType::Script;
    } else {
        return false;
    }

    record.firstBytesHex = HexUpper(prefix);
    record.remainderHashHex = HexUpper(record.objectSignature);
    record.objectSignaturePrefix = PrefixToUInt64(prefix);
    record.objectSignatureLength = static_cast<std::uint32_t>(kPrefixLength + record.remainderLength);
    record.avRecordSignature = entry.recordSignature;
    return true;
}

}

namespace pifms::service {

[[nodiscard]] bool AntivirusDatabase::LoadRawPackage(const std::vector<std::uint8_t>& packageData)
{
    return LoadRawPackage(packageData, {}, false) == AntivirusDatabaseLoadStatus::Ok;
}

[[nodiscard]] AntivirusDatabaseLoadStatus AntivirusDatabase::LoadRawPackage(
    const std::vector<std::uint8_t>& packageData,
    const std::wstring& certificatePath,
    bool requireSignatures
)
{
    BinaryReader packageReader(packageData);
    std::vector<std::uint8_t> manifest;
    std::vector<std::uint8_t> data;
    if (!ReadPackagePart(packageReader, manifest) ||
        !ReadPackagePart(packageReader, data) ||
        !packageReader.AtEnd()) {
        return AntivirusDatabaseLoadStatus::InvalidPackage;
    }

    std::int64_t releaseUnixSeconds = 0;
    std::vector<std::uint8_t> dataHash;
    std::vector<std::uint8_t> unsignedManifest;
    std::vector<std::uint8_t> manifestSignature;
    std::vector<ManifestEntry> entries;
    if (!ParseManifest(manifest, releaseUnixSeconds, dataHash, unsignedManifest, manifestSignature, entries)) {
        return AntivirusDatabaseLoadStatus::InvalidPackage;
    }

    if (requireSignatures && !VerifySignatureAnyCertificate(unsignedManifest, manifestSignature, certificatePath)) {
        return AntivirusDatabaseLoadStatus::InvalidManifestSignature;
    }

    std::vector<std::uint8_t> actualDataHash;
    if (!Sha256(data, actualDataHash) || actualDataHash != dataHash) {
        return AntivirusDatabaseLoadStatus::InvalidDataHash;
    }

    BinaryReader dataHeader(data);
    std::uint16_t version = 0;
    std::uint32_t recordCount = 0;
    if (!ReadMagic(dataHeader, kDataMagic, sizeof(kDataMagic)) ||
        !dataHeader.ReadUInt16(version) ||
        version != kBinaryVersion ||
        !dataHeader.ReadUInt32(recordCount) ||
        recordCount != entries.size()) {
        return AntivirusDatabaseLoadStatus::InvalidPackage;
    }
    const std::size_t payloadOffset = dataHeader.Position();

    std::map<std::uint64_t, std::vector<AntivirusRecord>> records;
    std::vector<std::string> invalidRecordIds;
    for (const ManifestEntry& entry : entries) {
        AntivirusRecord record;
        if (ParseRecord(data, payloadOffset, entry, record)) {
            if (requireSignatures &&
                !VerifySignatureAnyCertificate(
                    BytesFromString(BuildRecordSigningPayload(record)),
                    record.avRecordSignature,
                    certificatePath)) {
                if (!entry.id.empty()) {
                    invalidRecordIds.push_back(entry.id);
                }
                continue;
            }
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
    invalidRecordIds_ = std::move(invalidRecordIds);
    recordsByPrefix_ = std::move(records);
    BuildAutomaton();
    return AntivirusDatabaseLoadStatus::Ok;
}

[[nodiscard]] AntivirusDatabaseInfo AntivirusDatabase::GetInfo() const
{
    return info_;
}

[[nodiscard]] const std::vector<std::string>& AntivirusDatabase::InvalidRecordIds() const
{
    return invalidRecordIds_;
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

void AntivirusDatabase::MergeFrom(const AntivirusDatabase& other)
{
    for (const auto& pair : other.recordsByPrefix_) {
        auto& target = recordsByPrefix_[pair.first];
        target.insert(target.end(), pair.second.begin(), pair.second.end());
    }

    info_.recordCount = 0;
    for (const auto& pair : recordsByPrefix_) {
        info_.recordCount += static_cast<std::uint32_t>(pair.second.size());
    }
    invalidRecordIds_.clear();
    BuildAutomaton();
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
