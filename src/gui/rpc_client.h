#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace pifms::gui {

struct UserInfo {
    bool authenticated = false;
    std::uint64_t userId = 0;
    std::wstring username;
};

struct LicenseInfo {
    bool active = false;
    bool blocked = false;
    std::int64_t expirationUnixSeconds = 0;
    std::wstring expirationDate;
};

enum class ScanTargetType : long {
    File = 1,
    Directory = 2,
    FixedDrives = 3
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
    long objectType = 0;
    std::uint64_t offset = 0;
    std::wstring error;
};

[[nodiscard]] bool RequestServiceStop();
[[nodiscard]] long GetCurrentUser(UserInfo& userInfo);
[[nodiscard]] long Login(const std::wstring& username, const std::wstring& password, UserInfo& userInfo);
[[nodiscard]] long Logout();
[[nodiscard]] long GetLicenseInfo(LicenseInfo& licenseInfo);
[[nodiscard]] long ActivateProduct(const std::wstring& activationCode, LicenseInfo& licenseInfo);
[[nodiscard]] long EnsureAntivirusAvailable();
[[nodiscard]] long GetAntivirusDatabaseInfo(AntivirusDatabaseInfo& databaseInfo);
[[nodiscard]] long ScanFile(const std::wstring& path, std::vector<ScanResult>& results);
[[nodiscard]] long ScanDirectory(const std::wstring& path, std::vector<ScanResult>& results);
[[nodiscard]] long ScanFixedDrives(std::vector<ScanResult>& results);
[[nodiscard]] long ConfigureSchedule(ScanTargetType targetType, const std::wstring& path, std::uint32_t intervalMinutes);
[[nodiscard]] long ConfigureMonitoring(const std::wstring& path);
[[nodiscard]] long GetScheduledScanResults(std::vector<ScanResult>& results);
[[nodiscard]] long GetMonitoringScanResults(std::vector<ScanResult>& results);
[[nodiscard]] std::wstring RpcResultMessage(long result);

}
