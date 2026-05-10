#pragma once

#include "service/api_client.h"

#include <windows.h>

#include <cstdint>
#include <string>
#include <vector>

namespace pifms::service {

struct UserSnapshot {
    bool authenticated = false;
    std::uint64_t userId = 0;
    std::wstring username;
};

struct LicenseSnapshot {
    bool active = false;
    bool blocked = false;
    std::int64_t expirationUnixSeconds = 0;
    std::wstring expirationDate;
};

class SessionManager {
public:
    SessionManager();
    ~SessionManager();

    SessionManager(const SessionManager&) = delete;
    SessionManager& operator=(const SessionManager&) = delete;

    [[nodiscard]] UserSnapshot GetCurrentUser();
    [[nodiscard]] long Login(const std::wstring& username, const std::wstring& password, UserSnapshot& user);
    [[nodiscard]] long Logout();
    [[nodiscard]] long GetLicenseInfo(LicenseSnapshot& license);
    [[nodiscard]] long ActivateProduct(const std::wstring& activationCode, LicenseSnapshot& license);
    [[nodiscard]] long DownloadSignatureDatabase(std::vector<std::uint8_t>& packageData);
    [[nodiscard]] long DownloadSignatureRecords(
        const std::vector<std::string>& ids,
        std::vector<std::uint8_t>& packageData
    );

private:
    struct ParsedTicket {
        std::string rawResponse;
        std::int64_t lifetimeSeconds = 0;
        bool blocked = false;
        std::int64_t expirationUnixSeconds = 0;
        std::string expirationDate;
    };

    static DWORD WINAPI WorkerProc(void* context);

    [[nodiscard]] long RefreshTokens();
    [[nodiscard]] long QueryLicense(bool updateOnMissing);
    [[nodiscard]] long SaveTokenPair(const std::string& responseBody, const std::string& fallbackUsername);
    [[nodiscard]] static bool ParseTicketResponse(const std::string& responseBody, ParsedTicket& ticket);
    [[nodiscard]] static std::int64_t NowUnixSeconds();
    [[nodiscard]] static std::int64_t ComputeRefreshDue(std::int64_t expiryUnixSeconds, std::int64_t fallbackSeconds);
    [[nodiscard]] static std::int64_t ParseIso8601UnixSeconds(const std::string& value);
    [[nodiscard]] LicenseSnapshot BuildLicenseSnapshotLocked() const;
    [[nodiscard]] UserSnapshot BuildUserSnapshotLocked() const;

    void WorkerLoop();
    void ClearAuthLocked();
    void ClearLicenseLocked();
    void SignalWorker();

    ApiClient api_;
    CRITICAL_SECTION lock_ = {};
    HANDLE wakeEvent_ = nullptr;
    HANDLE workerThread_ = nullptr;
    bool stopping_ = false;

    std::string deviceId_;
    std::string accessToken_;
    std::string refreshToken_;
    std::string activationCode_;
    std::wstring username_;
    std::uint64_t userId_ = 0;
    std::int64_t accessExpiryUnixSeconds_ = 0;
    std::int64_t refreshExpiryUnixSeconds_ = 0;
    std::int64_t tokenRefreshDueUnixSeconds_ = 0;

    std::string licenseTicketResponse_;
    bool licenseBlocked_ = false;
    std::int64_t licenseExpirationUnixSeconds_ = 0;
    std::wstring licenseExpirationDate_;
    std::int64_t licenseRefreshDueUnixSeconds_ = 0;
};

}
