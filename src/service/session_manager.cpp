#include "service/session_manager.h"

#include "common/constants.h"
#include "common/device_info.h"
#include "common/text_utils.h"

#include <algorithm>
#include <cstdio>
#include <ctime>

namespace {

[[nodiscard]] bool IsHttpSuccess(const pifms::service::HttpResponse& response)
{
    return response.transportOk && response.statusCode >= 200 && response.statusCode < 300;
}

[[nodiscard]] long MapHttpFailure(const pifms::service::HttpResponse& response, long domainFailure)
{
    if (!response.transportOk) {
        return pifms::rpc_result::kNetworkError;
    }
    if (response.statusCode == 401 || response.statusCode == 403) {
        return pifms::rpc_result::kAuthenticationRequired;
    }
    if (response.statusCode == 404) {
        return pifms::rpc_result::kNoLicense;
    }
    return domainFailure;
}

class CriticalSectionLock {
public:
    explicit CriticalSectionLock(CRITICAL_SECTION& section) noexcept
        : section_(section)
    {
        EnterCriticalSection(&section_);
    }

    ~CriticalSectionLock()
    {
        LeaveCriticalSection(&section_);
    }

    CriticalSectionLock(const CriticalSectionLock&) = delete;
    CriticalSectionLock& operator=(const CriticalSectionLock&) = delete;

private:
    CRITICAL_SECTION& section_;
};

}

namespace pifms::service {

SessionManager::SessionManager()
{
    InitializeCriticalSection(&lock_);
    wakeEvent_ = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    deviceId_ = GetDeviceInfo().macAddress;
    if (wakeEvent_ != nullptr) {
        workerThread_ = CreateThread(nullptr, 0, WorkerProc, this, 0, nullptr);
    }
}

SessionManager::~SessionManager()
{
    {
        CriticalSectionLock lock(lock_);
        stopping_ = true;
    }

    SignalWorker();
    if (workerThread_ != nullptr) {
        WaitForSingleObject(workerThread_, 5000);
        CloseHandle(workerThread_);
    }

    if (wakeEvent_ != nullptr) {
        CloseHandle(wakeEvent_);
    }

    DeleteCriticalSection(&lock_);
}

[[nodiscard]] UserSnapshot SessionManager::GetCurrentUser()
{
    CriticalSectionLock lock(lock_);
    return BuildUserSnapshotLocked();
}

[[nodiscard]] long SessionManager::Login(const std::wstring& username, const std::wstring& password, UserSnapshot& user)
{
    const HttpResponse response = api_.Login(WideToUtf8(username), WideToUtf8(password), deviceId_);
    if (!IsHttpSuccess(response)) {
        return response.transportOk && response.statusCode == 401
            ? rpc_result::kAuthenticationFailed
            : MapHttpFailure(response, rpc_result::kAuthenticationFailed);
    }

    const long saveResult = SaveTokenPair(response.body, WideToUtf8(username));
    if (saveResult != rpc_result::kOk) {
        return saveResult;
    }

    {
        CriticalSectionLock lock(lock_);
        ClearLicenseLocked();
        user = BuildUserSnapshotLocked();
    }

    SignalWorker();
    return rpc_result::kOk;
}

[[nodiscard]] long SessionManager::Logout()
{
    {
        CriticalSectionLock lock(lock_);
        ClearAuthLocked();
    }

    SignalWorker();
    return rpc_result::kOk;
}

[[nodiscard]] long SessionManager::GetLicenseInfo(LicenseSnapshot& license)
{
    {
        CriticalSectionLock lock(lock_);
        if (accessToken_.empty()) {
            return rpc_result::kAuthenticationRequired;
        }
    }

    const long result = QueryLicense(true);
    {
        CriticalSectionLock lock(lock_);
        license = BuildLicenseSnapshotLocked();
    }
    return result;
}

[[nodiscard]] long SessionManager::ActivateProduct(const std::wstring& activationCode, LicenseSnapshot& license)
{
    std::string accessToken;
    const std::string activationCodeUtf8 = WideToUtf8(activationCode);
    {
        CriticalSectionLock lock(lock_);
        if (accessToken_.empty()) {
            return rpc_result::kAuthenticationRequired;
        }
        accessToken = accessToken_;
    }

    HttpResponse response = api_.ActivateLicense(accessToken, activationCodeUtf8);
    if (response.transportOk && response.statusCode == 401 && RefreshTokens() == rpc_result::kOk) {
        {
            CriticalSectionLock lock(lock_);
            accessToken = accessToken_;
        }
        response = api_.ActivateLicense(accessToken, activationCodeUtf8);
    }

    if (!IsHttpSuccess(response)) {
        if (response.transportOk && response.statusCode == 404) {
            return rpc_result::kActivationFailed;
        }
        return MapHttpFailure(response, rpc_result::kActivationFailed);
    }

    ParsedTicket ticket;
    if (!ParseTicketResponse(response.body, ticket)) {
        const long queryResult = QueryLicense(true);
        CriticalSectionLock lock(lock_);
        license = BuildLicenseSnapshotLocked();
        return queryResult;
    }

    {
        CriticalSectionLock lock(lock_);
        licenseTicketResponse_ = ticket.rawResponse;
        activationCode_ = activationCodeUtf8;
        licenseBlocked_ = ticket.blocked;
        licenseExpirationUnixSeconds_ = ticket.expirationUnixSeconds;
        licenseExpirationDate_ = Utf8ToWide(ticket.expirationDate);
        licenseRefreshDueUnixSeconds_ = NowUnixSeconds() + (std::max<std::int64_t>)(30, ticket.lifetimeSeconds - 30);
        license = BuildLicenseSnapshotLocked();
    }

    SignalWorker();
    return license.active ? rpc_result::kOk : rpc_result::kNoLicense;
}

[[nodiscard]] long SessionManager::RefreshTokens()
{
    std::string refreshToken;
    std::string username;
    {
        CriticalSectionLock lock(lock_);
        if (refreshToken_.empty()) {
            return rpc_result::kAuthenticationRequired;
        }
        refreshToken = refreshToken_;
        username = WideToUtf8(username_);
    }

    const HttpResponse response = api_.Refresh(refreshToken);
    if (!IsHttpSuccess(response)) {
        if (response.transportOk && (response.statusCode == 401 || response.statusCode == 403)) {
            CriticalSectionLock lock(lock_);
            ClearAuthLocked();
        }
        return MapHttpFailure(response, rpc_result::kAuthenticationRequired);
    }

    return SaveTokenPair(response.body, username);
}

[[nodiscard]] long SessionManager::QueryLicense(bool updateOnMissing)
{
    std::string accessToken;
    std::string activationCode;
    {
        CriticalSectionLock lock(lock_);
        if (accessToken_.empty()) {
            return rpc_result::kAuthenticationRequired;
        }
        accessToken = accessToken_;
        activationCode = activationCode_;
    }

    HttpResponse response = api_.CheckLicense(accessToken);
    if (response.transportOk && response.statusCode == 401 && RefreshTokens() == rpc_result::kOk) {
        {
            CriticalSectionLock lock(lock_);
            accessToken = accessToken_;
        }
        response = api_.CheckLicense(accessToken);
    }

    if (!IsHttpSuccess(response)) {
        if (response.transportOk && response.statusCode == 404 && !activationCode.empty()) {
            response = api_.ActivateLicense(accessToken, activationCode);
            if (response.transportOk && response.statusCode == 401 && RefreshTokens() == rpc_result::kOk) {
                {
                    CriticalSectionLock lock(lock_);
                    accessToken = accessToken_;
                }
                response = api_.ActivateLicense(accessToken, activationCode);
            }
            if (IsHttpSuccess(response)) {
                ParsedTicket ticket;
                if (!ParseTicketResponse(response.body, ticket)) {
                    return rpc_result::kInvalidServerResponse;
                }

                {
                    CriticalSectionLock lock(lock_);
                    licenseTicketResponse_ = ticket.rawResponse;
                    licenseBlocked_ = ticket.blocked;
                    licenseExpirationUnixSeconds_ = ticket.expirationUnixSeconds;
                    licenseExpirationDate_ = Utf8ToWide(ticket.expirationDate);
                    licenseRefreshDueUnixSeconds_ = NowUnixSeconds() + (std::max<std::int64_t>)(30, ticket.lifetimeSeconds - 30);
                }

                SignalWorker();
                return ticket.blocked ? rpc_result::kNoLicense : rpc_result::kOk;
            }
        }

        if (updateOnMissing && response.transportOk && response.statusCode == 404) {
            CriticalSectionLock lock(lock_);
            ClearLicenseLocked();
        }
        return MapHttpFailure(response, rpc_result::kNoLicense);
    }

    ParsedTicket ticket;
    if (!ParseTicketResponse(response.body, ticket)) {
        return rpc_result::kInvalidServerResponse;
    }

    {
        CriticalSectionLock lock(lock_);
        licenseTicketResponse_ = ticket.rawResponse;
        licenseBlocked_ = ticket.blocked;
        licenseExpirationUnixSeconds_ = ticket.expirationUnixSeconds;
        licenseExpirationDate_ = Utf8ToWide(ticket.expirationDate);
        licenseRefreshDueUnixSeconds_ = NowUnixSeconds() + (std::max<std::int64_t>)(30, ticket.lifetimeSeconds - 30);
    }

    SignalWorker();
    return ticket.blocked ? rpc_result::kNoLicense : rpc_result::kOk;
}

[[nodiscard]] long SessionManager::SaveTokenPair(const std::string& responseBody, const std::string& fallbackUsername)
{
    const std::optional<std::string> accessToken = ExtractJsonString(responseBody, "accessToken");
    const std::optional<std::string> refreshToken = ExtractJsonString(responseBody, "refreshToken");
    if (!accessToken.has_value() || !refreshToken.has_value()) {
        return rpc_result::kInvalidServerResponse;
    }

    const std::optional<std::int64_t> accessExpiry = ExtractJwtExpiryUnixSeconds(*accessToken);
    const std::optional<std::int64_t> refreshExpiry = ExtractJwtExpiryUnixSeconds(*refreshToken);
    if (!accessExpiry.has_value() || !refreshExpiry.has_value()) {
        return rpc_result::kInvalidServerResponse;
    }

    const std::optional<std::string> jwtUsername = ExtractJwtSubject(*accessToken);
    const std::optional<std::int64_t> userId = ExtractJwtInt64Claim(*accessToken, "uid");

    {
        CriticalSectionLock lock(lock_);
        accessToken_ = *accessToken;
        refreshToken_ = *refreshToken;
        username_ = Utf8ToWide(jwtUsername.value_or(fallbackUsername));
        userId_ = userId.has_value() && *userId > 0 ? static_cast<std::uint64_t>(*userId) : 0;
        accessExpiryUnixSeconds_ = *accessExpiry;
        refreshExpiryUnixSeconds_ = *refreshExpiry;
        tokenRefreshDueUnixSeconds_ = ComputeRefreshDue(accessExpiryUnixSeconds_, 60);
    }

    SignalWorker();
    return rpc_result::kOk;
}

[[nodiscard]] bool SessionManager::ParseTicketResponse(const std::string& responseBody, ParsedTicket& ticket)
{
    const std::optional<std::string> ticketObject = ExtractJsonObject(responseBody, "ticket");
    const std::optional<std::string> signature = ExtractJsonString(responseBody, "signature");
    if (!ticketObject.has_value() || !signature.has_value()) {
        return false;
    }

    const std::optional<std::int64_t> lifetime = ExtractJsonInt64(*ticketObject, "ticketLifetimeSeconds");
    const std::optional<bool> blocked = ExtractJsonBool(*ticketObject, "blocked");
    const std::optional<std::string> expirationDate = ExtractJsonString(*ticketObject, "expirationDate");
    if (!lifetime.has_value() || !blocked.has_value() || !expirationDate.has_value()) {
        return false;
    }

    ticket.rawResponse = responseBody;
    ticket.lifetimeSeconds = *lifetime;
    ticket.blocked = *blocked;
    ticket.expirationDate = *expirationDate;
    ticket.expirationUnixSeconds = ParseIso8601UnixSeconds(*expirationDate);
    return true;
}

[[nodiscard]] std::int64_t SessionManager::NowUnixSeconds()
{
    return static_cast<std::int64_t>(std::time(nullptr));
}

[[nodiscard]] std::int64_t SessionManager::ComputeRefreshDue(
    std::int64_t expiryUnixSeconds,
    std::int64_t fallbackSeconds
)
{
    const std::int64_t now = NowUnixSeconds();
    const std::int64_t remaining = expiryUnixSeconds - now;
    if (remaining <= 0) {
        return now + 5;
    }

    const std::int64_t safetyWindow = (std::min<std::int64_t>)(60, (std::max<std::int64_t>)(10, remaining / 5));
    return (std::max)(now + 5, expiryUnixSeconds - (std::max)(safetyWindow, fallbackSeconds));
}

[[nodiscard]] std::int64_t SessionManager::ParseIso8601UnixSeconds(const std::string& value)
{
    int year = 0;
    int month = 0;
    int day = 0;
    int hour = 0;
    int minute = 0;
    int second = 0;

    if (sscanf_s(
            value.c_str(),
            "%4d-%2d-%2dT%2d:%2d:%2d",
            &year,
            &month,
            &day,
            &hour,
            &minute,
            &second) != 6) {
        return 0;
    }

    std::tm timeValue = {};
    timeValue.tm_year = year - 1900;
    timeValue.tm_mon = month - 1;
    timeValue.tm_mday = day;
    timeValue.tm_hour = hour;
    timeValue.tm_min = minute;
    timeValue.tm_sec = second;
    return static_cast<std::int64_t>(_mkgmtime(&timeValue));
}

[[nodiscard]] LicenseSnapshot SessionManager::BuildLicenseSnapshotLocked() const
{
    const bool hasTicket = !licenseTicketResponse_.empty();
    const bool isExpired = licenseExpirationUnixSeconds_ > 0 &&
        licenseExpirationUnixSeconds_ <= NowUnixSeconds();

    return LicenseSnapshot{
        hasTicket && !licenseBlocked_ && !isExpired,
        licenseBlocked_,
        licenseExpirationUnixSeconds_,
        licenseExpirationDate_
    };
}

[[nodiscard]] UserSnapshot SessionManager::BuildUserSnapshotLocked() const
{
    return UserSnapshot{
        !accessToken_.empty() && !refreshToken_.empty(),
        userId_,
        username_
    };
}

void SessionManager::WorkerLoop()
{
    for (;;) {
        DWORD waitMilliseconds = INFINITE;
        bool shouldRefreshToken = false;
        bool shouldRefreshLicense = false;

        {
            CriticalSectionLock lock(lock_);
            if (stopping_) {
                return;
            }

            const std::int64_t now = NowUnixSeconds();
            if (!refreshToken_.empty() && tokenRefreshDueUnixSeconds_ > 0) {
                shouldRefreshToken = tokenRefreshDueUnixSeconds_ <= now;
                const std::int64_t delaySeconds = (std::max<std::int64_t>)(1, tokenRefreshDueUnixSeconds_ - now);
                waitMilliseconds = static_cast<DWORD>((std::min<std::int64_t>)(delaySeconds * 1000, waitMilliseconds));
            }

            if (!licenseTicketResponse_.empty() && licenseRefreshDueUnixSeconds_ > 0) {
                shouldRefreshLicense = licenseRefreshDueUnixSeconds_ <= now;
                const std::int64_t delaySeconds = (std::max<std::int64_t>)(1, licenseRefreshDueUnixSeconds_ - now);
                waitMilliseconds = static_cast<DWORD>((std::min<std::int64_t>)(delaySeconds * 1000, waitMilliseconds));
            }
        }

        if (shouldRefreshToken) {
            static_cast<void>(RefreshTokens());
            continue;
        }

        if (shouldRefreshLicense) {
            static_cast<void>(QueryLicense(true));
            continue;
        }

        WaitForSingleObject(wakeEvent_, waitMilliseconds);
    }
}

void SessionManager::ClearAuthLocked()
{
    accessToken_.clear();
    refreshToken_.clear();
    activationCode_.clear();
    username_.clear();
    userId_ = 0;
    accessExpiryUnixSeconds_ = 0;
    refreshExpiryUnixSeconds_ = 0;
    tokenRefreshDueUnixSeconds_ = 0;
    ClearLicenseLocked();
}

void SessionManager::ClearLicenseLocked()
{
    licenseTicketResponse_.clear();
    licenseBlocked_ = false;
    licenseExpirationUnixSeconds_ = 0;
    licenseExpirationDate_.clear();
    licenseRefreshDueUnixSeconds_ = 0;
}

void SessionManager::SignalWorker()
{
    if (wakeEvent_ != nullptr) {
        SetEvent(wakeEvent_);
    }
}

DWORD WINAPI SessionManager::WorkerProc(void* context)
{
    static_cast<SessionManager*>(context)->WorkerLoop();
    return 0;
}

}
