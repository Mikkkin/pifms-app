#pragma once

namespace pifms {

inline constexpr wchar_t kServiceName[] = L"PIFMSService";
inline constexpr wchar_t kServiceDisplayName[] = L"PIFMS Application Service";
inline constexpr wchar_t kAppExecutableName[] = L"PIFMSApp.exe";
inline constexpr wchar_t kRpcEndpoint[] = L"PIFMSServiceRpc";
inline constexpr wchar_t kServiceChildArg[] = L"--service-child";
inline constexpr wchar_t kSilentArg[] = L"--silent";
inline constexpr wchar_t kDefaultApiBaseUrl[] = L"https://localhost:8443";
inline constexpr wchar_t kDefaultProductId[] = L"00000000-0000-0000-0000-000000000000";

namespace rpc_result {
inline constexpr long kOk = 0;
inline constexpr long kAuthenticationRequired = 1;
inline constexpr long kAuthenticationFailed = 2;
inline constexpr long kNoLicense = 3;
inline constexpr long kActivationFailed = 4;
inline constexpr long kNetworkError = 5;
inline constexpr long kInvalidServerResponse = 6;
inline constexpr long kInternalError = 7;
}

}
