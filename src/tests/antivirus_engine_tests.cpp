#include "service/antivirus_engine.h"

#include <windows.h>
#include <wincrypt.h>

#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <sstream>
#include <string>
#include <vector>

namespace {

constexpr std::uint8_t kManifestMagic[] = {
    'M', 'F', '-', 'K', 'h', 'a', 'n', 'g', 'i', 'l', 'd', 'i', 'n'
};
constexpr std::uint8_t kDataMagic[] = {
    'D', 'B', '-', 'K', 'h', 'a', 'n', 'g', 'i', 'l', 'd', 'i', 'n'
};

void WriteUInt8(std::vector<std::uint8_t>& out, std::uint8_t value)
{
    out.push_back(value);
}

void WriteUInt16(std::vector<std::uint8_t>& out, std::uint16_t value)
{
    out.push_back(static_cast<std::uint8_t>((value >> 8) & 0xFF));
    out.push_back(static_cast<std::uint8_t>(value & 0xFF));
}

void WriteUInt32(std::vector<std::uint8_t>& out, std::uint32_t value)
{
    out.push_back(static_cast<std::uint8_t>((value >> 24) & 0xFF));
    out.push_back(static_cast<std::uint8_t>((value >> 16) & 0xFF));
    out.push_back(static_cast<std::uint8_t>((value >> 8) & 0xFF));
    out.push_back(static_cast<std::uint8_t>(value & 0xFF));
}

void WriteUInt64(std::vector<std::uint8_t>& out, std::uint64_t value)
{
    for (int shift = 56; shift >= 0; shift -= 8) {
        out.push_back(static_cast<std::uint8_t>((value >> shift) & 0xFF));
    }
}

void WriteRaw(std::vector<std::uint8_t>& out, const std::uint8_t* data, std::size_t size)
{
    out.insert(out.end(), data, data + size);
}

void WriteArray(std::vector<std::uint8_t>& out, const std::vector<std::uint8_t>& value)
{
    WriteUInt32(out, static_cast<std::uint32_t>(value.size()));
    out.insert(out.end(), value.begin(), value.end());
}

void WriteString(std::vector<std::uint8_t>& out, const char* value)
{
    const std::string text(value);
    WriteArray(out, std::vector<std::uint8_t>(text.begin(), text.end()));
}

std::vector<std::uint8_t> Sha256(const std::vector<std::uint8_t>& data)
{
    HCRYPTPROV provider = 0;
    HCRYPTHASH hashHandle = 0;
    std::vector<std::uint8_t> hash(32);
    if (!CryptAcquireContextW(&provider, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        return {};
    }
    if (!CryptCreateHash(provider, CALG_SHA_256, 0, 0, &hashHandle)) {
        CryptReleaseContext(provider, 0);
        return {};
    }
    if (!data.empty()) {
        CryptHashData(hashHandle, data.data(), static_cast<DWORD>(data.size()), 0);
    }
    DWORD hashLength = static_cast<DWORD>(hash.size());
    CryptGetHashParam(hashHandle, HP_HASHVAL, hash.data(), &hashLength, 0);
    hash.resize(hashLength);
    CryptDestroyHash(hashHandle);
    CryptReleaseContext(provider, 0);
    return hash;
}

std::vector<std::uint8_t> BuildPackage(
    std::uint64_t offsetBegin,
    std::uint64_t offsetEnd,
    const std::vector<std::uint8_t>& fragment,
    const char* threatName,
    const char* fileType
)
{
    const std::vector<std::uint8_t> prefix(fragment.begin(), fragment.begin() + 8);
    const std::vector<std::uint8_t> signature = Sha256(fragment);

    std::vector<std::uint8_t> record;
    WriteString(record, threatName);
    WriteArray(record, prefix);
    WriteArray(record, signature);
    WriteUInt64(record, fragment.size() - 8);
    WriteString(record, fileType);
    WriteUInt64(record, offsetBegin);
    WriteUInt64(record, offsetEnd);

    std::vector<std::uint8_t> data;
    WriteRaw(data, kDataMagic, sizeof(kDataMagic));
    WriteUInt16(data, 1);
    WriteUInt32(data, 1);
    const std::uint32_t recordOffset = 0;
    data.insert(data.end(), record.begin(), record.end());

    const std::vector<std::uint8_t> dataHash = Sha256(data);
    std::vector<std::uint8_t> manifest;
    WriteRaw(manifest, kManifestMagic, sizeof(kManifestMagic));
    WriteUInt16(manifest, 1);
    WriteUInt8(manifest, 1);
    WriteUInt64(manifest, 1770000000000ULL);
    WriteUInt64(manifest, UINT64_MAX);
    WriteUInt32(manifest, 1);
    WriteRaw(manifest, dataHash.data(), dataHash.size());
    for (int index = 0; index < 16; ++index) {
        WriteUInt8(manifest, 0);
    }
    WriteUInt8(manifest, 1);
    WriteUInt64(manifest, 1770000000000ULL);
    WriteUInt64(manifest, recordOffset);
    WriteUInt32(manifest, static_cast<std::uint32_t>(record.size()));
    WriteArray(manifest, {1, 2, 3});
    WriteArray(manifest, {4});

    std::vector<std::uint8_t> package;
    WriteArray(package, manifest);
    WriteArray(package, data);
    return package;
}

std::vector<std::uint8_t> BuildPackage(std::uint64_t offsetBegin, std::uint64_t offsetEnd)
{
    return BuildPackage(offsetBegin, offsetEnd, {1, 2, 3, 4, 5, 6, 7, 8, 9, 10}, "Trojan.Test", "script");
}

std::istringstream StreamFromBytes(const std::vector<std::uint8_t>& bytes)
{
    return std::istringstream(std::string(bytes.begin(), bytes.end()));
}

std::wstring ExecutableDirectory()
{
    std::wstring path(MAX_PATH, L'\0');
    for (;;) {
        const DWORD length = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
        if (length == 0) {
            return {};
        }
        if (length < path.size() - 1) {
            path.resize(length);
            break;
        }
        path.resize(path.size() * 2);
    }

    const std::size_t separator = path.find_last_of(L"\\/");
    if (separator == std::wstring::npos) {
        return {};
    }
    path.resize(separator);
    return path;
}

std::wstring JoinPath(const std::wstring& base, const wchar_t* relative)
{
    std::filesystem::path path(base);
    path /= relative;
    return path.wstring();
}

std::vector<std::uint8_t> ReadFile(const std::wstring& path)
{
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        return {};
    }
    return std::vector<std::uint8_t>(
        std::istreambuf_iterator<char>(file),
        std::istreambuf_iterator<char>()
    );
}

bool Expect(bool condition, const char* name)
{
    if (!condition) {
        std::cerr << name << '\n';
        return false;
    }
    return true;
}

}

int main()
{
    pifms::service::AntivirusDatabase database;
    if (!Expect(database.LoadRawPackage(BuildPackage(4, 4)), "database load failed")) {
        return 1;
    }

    pifms::service::AntivirusEngine engine(database);
    std::vector<std::uint8_t> clean(24, 0);
    auto cleanStream = StreamFromBytes(clean);
    if (!Expect(!engine.ScanStream(cleanStream, L"clean.js", pifms::service::ScanObjectType::Script).malicious, "clean file detected")) {
        return 1;
    }

    std::vector<std::uint8_t> infected(24, 0);
    const std::vector<std::uint8_t> fragment = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    std::copy(fragment.begin(), fragment.end(), infected.begin() + 4);
    auto wrongTypeStream = StreamFromBytes(infected);
    if (!Expect(!engine.ScanStream(wrongTypeStream, L"sample.exe", pifms::service::ScanObjectType::Pe).malicious, "wrong type detected")) {
        return 1;
    }

    pifms::service::AntivirusDatabase wrongOffsetDatabase;
    if (!Expect(wrongOffsetDatabase.LoadRawPackage(BuildPackage(5, 5)), "wrong offset database load failed")) {
        return 1;
    }
    pifms::service::AntivirusEngine wrongOffsetEngine(wrongOffsetDatabase);
    auto wrongOffsetStream = StreamFromBytes(infected);
    if (!Expect(!wrongOffsetEngine.ScanStream(wrongOffsetStream, L"sample.js", pifms::service::ScanObjectType::Script).malicious, "wrong offset detected")) {
        return 1;
    }

    auto infectedStream = StreamFromBytes(infected);
    const pifms::service::ScanResult infectedResult = engine.ScanStream(
        infectedStream,
        L"sample.js",
        pifms::service::ScanObjectType::Script
    );
    if (!Expect(infectedResult.malicious && infectedResult.offset == 4, "infected file not detected")) {
        return 1;
    }

    const std::string eicarText = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
    const std::vector<std::uint8_t> eicarBytes(eicarText.begin(), eicarText.end());
    pifms::service::AntivirusDatabase eicarDatabase;
    if (!Expect(
            eicarDatabase.LoadRawPackage(BuildPackage(0, 0, eicarBytes, "EICAR Test File", "com")),
            "eicar database load failed")) {
        return 1;
    }

    pifms::service::AntivirusEngine eicarEngine(eicarDatabase);
    auto eicarStream = StreamFromBytes(eicarBytes);
    const pifms::service::ScanResult eicarResult = eicarEngine.ScanStream(
        eicarStream,
        L"test.com",
        pifms::service::ScanObjectType::Com
    );
    if (!Expect(eicarResult.malicious && eicarResult.offset == 0, "eicar file not detected")) {
        return 1;
    }

    const std::wstring executableDirectory = ExecutableDirectory();
    const std::wstring certificatePath = JoinPath(executableDirectory, L"resources\\avdb\\signing.crt");
    const std::vector<std::uint8_t> defaultPackage = ReadFile(JoinPath(executableDirectory, L"resources\\avdb\\default.pifmsdb"));
    if (!Expect(!defaultPackage.empty(), "default package not found")) {
        return 1;
    }

    pifms::service::AntivirusDatabase strictDatabase;
    if (!Expect(
            strictDatabase.LoadRawPackage(defaultPackage, certificatePath, true) ==
                pifms::service::AntivirusDatabaseLoadStatus::Ok,
            "signed default database load failed")) {
        return 1;
    }

    pifms::service::AntivirusEngine strictEngine(strictDatabase);
    auto strictEicarStream = StreamFromBytes(eicarBytes);
    if (!Expect(
            strictEngine.ScanStream(strictEicarStream, L"test.com", pifms::service::ScanObjectType::Com).malicious,
            "signed default database eicar not detected")) {
        return 1;
    }

    std::vector<std::uint8_t> badManifest = defaultPackage;
    if (badManifest.size() > 24) {
        badManifest[24] ^= 0x01;
    }
    pifms::service::AntivirusDatabase badManifestDatabase;
    if (!Expect(
            badManifestDatabase.LoadRawPackage(badManifest, certificatePath, true) ==
                pifms::service::AntivirusDatabaseLoadStatus::InvalidManifestSignature,
            "bad manifest signature accepted")) {
        return 1;
    }

    std::vector<std::uint8_t> badData = defaultPackage;
    if (!badData.empty()) {
        badData.back() ^= 0x01;
    }
    pifms::service::AntivirusDatabase badDataDatabase;
    if (!Expect(
            badDataDatabase.LoadRawPackage(badData, certificatePath, true) ==
                pifms::service::AntivirusDatabaseLoadStatus::InvalidDataHash,
            "bad data hash accepted")) {
        return 1;
    }

    const std::vector<std::uint8_t> invalidRecordPackage =
        ReadFile(JoinPath(executableDirectory, L"test_resources\\invalid-record-signature.pifmsdb"));
    if (!Expect(!invalidRecordPackage.empty(), "invalid record package not found")) {
        return 1;
    }

    pifms::service::AntivirusDatabase invalidRecordDatabase;
    if (!Expect(
            invalidRecordDatabase.LoadRawPackage(invalidRecordPackage, certificatePath, true) ==
                pifms::service::AntivirusDatabaseLoadStatus::Ok,
            "invalid record package rejected")) {
        return 1;
    }
    if (!Expect(invalidRecordDatabase.GetInfo().recordCount == 0, "invalid record was not skipped")) {
        return 1;
    }

    return 0;
}
