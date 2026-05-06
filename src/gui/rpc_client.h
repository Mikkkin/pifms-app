#pragma once

#include <cstdint>
#include <string>

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

[[nodiscard]] bool RequestServiceStop();
[[nodiscard]] long GetCurrentUser(UserInfo& userInfo);
[[nodiscard]] long Login(const std::wstring& username, const std::wstring& password, UserInfo& userInfo);
[[nodiscard]] long Logout();
[[nodiscard]] long GetLicenseInfo(LicenseInfo& licenseInfo);
[[nodiscard]] long ActivateProduct(const std::wstring& activationCode, LicenseInfo& licenseInfo);
[[nodiscard]] long EnsureAntivirusAvailable();
[[nodiscard]] std::wstring RpcResultMessage(long result);

}
