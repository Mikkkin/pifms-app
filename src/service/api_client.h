#pragma once

#include <windows.h>
#include <winhttp.h>

#include <cstdint>
#include <string>
#include <vector>

namespace pifms::service {

struct HttpResponse {
    bool transportOk = false;
    DWORD statusCode = 0;
    std::string contentType;
    std::string body;
};

class ApiClient {
public:
    ApiClient();

    [[nodiscard]] HttpResponse Login(
        const std::string& username,
        const std::string& password,
        const std::string& deviceId
    ) const;
    [[nodiscard]] HttpResponse Refresh(const std::string& refreshToken) const;
    [[nodiscard]] HttpResponse CheckLicense(const std::string& accessToken) const;
    [[nodiscard]] HttpResponse ActivateLicense(
        const std::string& accessToken,
        const std::string& activationCode
    ) const;
    [[nodiscard]] HttpResponse DownloadSignatureDatabase(const std::string& accessToken) const;
    [[nodiscard]] HttpResponse DownloadSignatureRecords(
        const std::string& accessToken,
        const std::vector<std::string>& ids
    ) const;

private:
    [[nodiscard]] HttpResponse PostJson(
        const wchar_t* path,
        const std::string& body,
        const std::string& bearerToken = {},
        const std::string& extraHeaders = {}
    ) const;
    [[nodiscard]] HttpResponse SendRequest(
        const wchar_t* method,
        const wchar_t* path,
        const std::string& body,
        const std::string& bearerToken,
        const std::string& acceptHeader,
        const std::string& extraHeaders
    ) const;

    std::wstring host_;
    std::wstring basePath_;
    INTERNET_PORT port_ = INTERNET_DEFAULT_HTTPS_PORT;
    bool secure_ = true;
    bool allowInsecureTls_ = true;
    std::string productId_;
    std::string deviceMac_;
    std::string deviceName_;
};

}
