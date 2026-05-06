#include "service/api_client.h"

#include "common/constants.h"
#include "common/device_info.h"
#include "common/text_utils.h"

#include <windows.h>
#include <winhttp.h>

#include <algorithm>
#include <string>
#include <utility>
#include <vector>

namespace {

class InternetHandle {
public:
    explicit InternetHandle(HINTERNET handle = nullptr) noexcept
        : handle_(handle)
    {
    }

    ~InternetHandle()
    {
        if (handle_ != nullptr) {
            WinHttpCloseHandle(handle_);
        }
    }

    InternetHandle(const InternetHandle&) = delete;
    InternetHandle& operator=(const InternetHandle&) = delete;

    [[nodiscard]] HINTERNET Get() const noexcept
    {
        return handle_;
    }

    [[nodiscard]] explicit operator bool() const noexcept
    {
        return handle_ != nullptr;
    }

private:
    HINTERNET handle_ = nullptr;
};

[[nodiscard]] std::wstring JoinPath(const std::wstring& basePath, const wchar_t* path)
{
    if (basePath.empty() || basePath == L"/") {
        return path;
    }

    std::wstring result = basePath;
    if (result.back() == L'/' && path[0] == L'/') {
        result.pop_back();
    } else if (result.back() != L'/' && path[0] != L'/') {
        result.push_back(L'/');
    }

    result += path;
    return result;
}

[[nodiscard]] bool ParseBaseUrl(
    const std::wstring& baseUrl,
    std::wstring& host,
    std::wstring& path,
    INTERNET_PORT& port,
    bool& secure
)
{
    URL_COMPONENTSW components = {};
    components.dwStructSize = sizeof(components);

    wchar_t hostBuffer[256] = {};
    wchar_t pathBuffer[1024] = {};
    components.lpszHostName = hostBuffer;
    components.dwHostNameLength = ARRAYSIZE(hostBuffer);
    components.lpszUrlPath = pathBuffer;
    components.dwUrlPathLength = ARRAYSIZE(pathBuffer);

    if (!WinHttpCrackUrl(baseUrl.c_str(), static_cast<DWORD>(baseUrl.size()), 0, &components)) {
        return false;
    }

    host.assign(components.lpszHostName, components.dwHostNameLength);
    path.assign(components.lpszUrlPath, components.dwUrlPathLength);
    port = components.nPort;
    secure = components.nScheme == INTERNET_SCHEME_HTTPS;

    if (path.empty()) {
        path = L"/";
    }

    return !host.empty();
}

[[nodiscard]] std::string BuildJsonProperty(const char* key, const std::string& value)
{
    return "\"" + std::string(key) + "\":\"" + pifms::JsonEscape(value) + "\"";
}

}

namespace pifms::service {

ApiClient::ApiClient()
{
    std::wstring baseUrl = ReadEnvironmentString(L"PIFMS_API_BASE_URL", pifms::kDefaultApiBaseUrl);
    if (!ParseBaseUrl(baseUrl, host_, basePath_, port_, secure_)) {
        static_cast<void>(ParseBaseUrl(pifms::kDefaultApiBaseUrl, host_, basePath_, port_, secure_));
    }

    allowInsecureTls_ = ReadEnvironmentFlag(L"PIFMS_ALLOW_INSECURE_TLS", true);
    productId_ = WideToUtf8(ReadEnvironmentString(L"PIFMS_PRODUCT_ID", pifms::kDefaultProductId));

    const DeviceInfo device = GetDeviceInfo();
    deviceMac_ = device.macAddress;
    deviceName_ = device.name;
}

[[nodiscard]] HttpResponse ApiClient::Login(
    const std::string& username,
    const std::string& password,
    const std::string& deviceId
) const
{
    const std::string body = "{" +
        BuildJsonProperty("username", username) + "," +
        BuildJsonProperty("password", password) +
        "}";
    const std::string headers = "X-Device-Id: " + deviceId + "\r\n";
    return PostJson(L"/api/auth/login", body, {}, headers);
}

[[nodiscard]] HttpResponse ApiClient::Refresh(const std::string& refreshToken) const
{
    const std::string body = "{" + BuildJsonProperty("refreshToken", refreshToken) + "}";
    return PostJson(L"/api/auth/refresh", body);
}

[[nodiscard]] HttpResponse ApiClient::CheckLicense(const std::string& accessToken) const
{
    const std::string body = "{" +
        BuildJsonProperty("deviceMac", deviceMac_) + "," +
        BuildJsonProperty("productId", productId_) +
        "}";
    return PostJson(L"/api/licenses/check", body, accessToken);
}

[[nodiscard]] HttpResponse ApiClient::ActivateLicense(
    const std::string& accessToken,
    const std::string& activationCode
) const
{
    const std::string body = "{" +
        BuildJsonProperty("activationKey", activationCode) + "," +
        BuildJsonProperty("deviceMac", deviceMac_) + "," +
        BuildJsonProperty("deviceName", deviceName_) +
        "}";
    return PostJson(L"/api/licenses/activate", body, accessToken);
}

[[nodiscard]] HttpResponse ApiClient::PostJson(
    const wchar_t* path,
    const std::string& body,
    const std::string& bearerToken,
    const std::string& extraHeaders
) const
{
    HttpResponse response;

    InternetHandle session(WinHttpOpen(
        L"PIFMSService/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0
    ));
    if (!session) {
        return response;
    }

    InternetHandle connection(WinHttpConnect(session.Get(), host_.c_str(), port_, 0));
    if (!connection) {
        return response;
    }

    const std::wstring requestPath = JoinPath(basePath_, path);
    InternetHandle request(WinHttpOpenRequest(
        connection.Get(),
        L"POST",
        requestPath.c_str(),
        nullptr,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        secure_ ? WINHTTP_FLAG_SECURE : 0
    ));
    if (!request) {
        return response;
    }

    if (secure_ && allowInsecureTls_) {
        DWORD flags =
            SECURITY_FLAG_IGNORE_UNKNOWN_CA |
            SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
            SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
            SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
        WinHttpSetOption(request.Get(), WINHTTP_OPTION_SECURITY_FLAGS, &flags, sizeof(flags));
    }

    std::string headers = "Content-Type: application/json\r\nAccept: application/json\r\n";
    headers += extraHeaders;
    if (!bearerToken.empty()) {
        headers += "Authorization: Bearer " + bearerToken + "\r\n";
    }

    const std::wstring wideHeaders = Utf8ToWide(headers);
    const BOOL sent = WinHttpSendRequest(
        request.Get(),
        wideHeaders.c_str(),
        static_cast<DWORD>(wideHeaders.size()),
        const_cast<char*>(body.data()),
        static_cast<DWORD>(body.size()),
        static_cast<DWORD>(body.size()),
        0
    );
    if (!sent || !WinHttpReceiveResponse(request.Get(), nullptr)) {
        return response;
    }

    DWORD statusCode = 0;
    DWORD statusCodeSize = sizeof(statusCode);
    if (WinHttpQueryHeaders(
            request.Get(),
            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            WINHTTP_HEADER_NAME_BY_INDEX,
            &statusCode,
            &statusCodeSize,
            WINHTTP_NO_HEADER_INDEX)) {
        response.statusCode = statusCode;
    }

    for (;;) {
        DWORD available = 0;
        if (!WinHttpQueryDataAvailable(request.Get(), &available)) {
            return response;
        }

        if (available == 0) {
            break;
        }

        std::string chunk(available, '\0');
        DWORD read = 0;
        if (!WinHttpReadData(request.Get(), chunk.data(), available, &read)) {
            return response;
        }

        chunk.resize(read);
        response.body += chunk;
    }

    response.transportOk = true;
    return response;
}

}
