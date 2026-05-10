#include "gui/rpc_client.h"

#include "common/constants.h"

#include <rpc.h>

#include <cstdlib>
#include <string>

#include "rpc/pifms_control_api.h"

extern "C" void* __RPC_USER midl_user_allocate(size_t size)
{
    return std::malloc(size);
}

extern "C" void __RPC_USER midl_user_free(void* pointer)
{
    std::free(pointer);
}

namespace pifms::gui {

class RpcBinding {
public:
    RpcBinding()
    {
        RPC_WSTR stringBinding = nullptr;
        RPC_STATUS status = RpcStringBindingComposeW(
            nullptr,
            reinterpret_cast<RPC_WSTR>(const_cast<wchar_t*>(L"ncalrpc")),
            nullptr,
            reinterpret_cast<RPC_WSTR>(const_cast<wchar_t*>(pifms::kRpcEndpoint)),
            nullptr,
            &stringBinding
        );

        if (status != RPC_S_OK) {
            return;
        }

        status = RpcBindingFromStringBindingW(stringBinding, &binding_);
        RpcStringFreeW(&stringBinding);
        if (status != RPC_S_OK) {
            binding_ = nullptr;
        }
    }

    ~RpcBinding()
    {
        if (binding_ != nullptr) {
            RpcBindingFree(&binding_);
        }
    }

    RpcBinding(const RpcBinding&) = delete;
    RpcBinding& operator=(const RpcBinding&) = delete;

    [[nodiscard]] handle_t Get() const noexcept
    {
        return binding_;
    }

    [[nodiscard]] explicit operator bool() const noexcept
    {
        return binding_ != nullptr;
    }

private:
    handle_t binding_ = nullptr;
};

[[nodiscard]] UserInfo ConvertUserInfo(const PifmsRpcUserInfo& rpcUserInfo)
{
    return UserInfo{
        rpcUserInfo.authenticated != 0,
        rpcUserInfo.userId,
        rpcUserInfo.username
    };
}

[[nodiscard]] LicenseInfo ConvertLicenseInfo(const PifmsRpcLicenseInfo& rpcLicenseInfo)
{
    return LicenseInfo{
        rpcLicenseInfo.active != 0,
        rpcLicenseInfo.blocked != 0,
        rpcLicenseInfo.expirationUnixSeconds,
        rpcLicenseInfo.expirationDate
    };
}

[[nodiscard]] AntivirusDatabaseInfo ConvertDatabaseInfo(const PifmsRpcAvDatabaseInfo& rpcDatabaseInfo)
{
    return AntivirusDatabaseInfo{
        rpcDatabaseInfo.loaded != 0,
        rpcDatabaseInfo.releaseUnixSeconds,
        rpcDatabaseInfo.releaseDate,
        rpcDatabaseInfo.recordCount
    };
}

[[nodiscard]] std::vector<ScanResult> ConvertScanResults(const PifmsRpcScanResults& rpcResults)
{
    std::vector<ScanResult> results;
    results.reserve(rpcResults.count);
    for (unsigned long index = 0; index < rpcResults.count && index < pifms::kRpcScanResultCapacity; ++index) {
        const PifmsRpcScanResult& item = rpcResults.items[index];
        results.push_back(ScanResult{
            item.path,
            item.scanned != 0,
            item.malicious != 0,
            item.threatName,
            item.objectType,
            item.offset,
            item.error
        });
    }
    return results;
}

[[nodiscard]] long RpcExceptionToResult(RPC_STATUS status)
{
    return status == RPC_S_OK ? pifms::rpc_result::kOk : pifms::rpc_result::kNetworkError;
}

[[nodiscard]] RPC_STATUS CallStopService(handle_t binding)
{
    RPC_STATUS status = RPC_S_OK;
    RpcTryExcept
    {
        PifmsStopService(binding);
        status = RPC_S_OK;
    }
    RpcExcept(1)
    {
        status = RpcExceptionCode();
    }
    RpcEndExcept

    return status;
}

[[nodiscard]] long CallGetCurrentUser(handle_t binding, PifmsRpcUserInfo* rpcUserInfo)
{
    long result = pifms::rpc_result::kNetworkError;
    RpcTryExcept
    {
        result = PifmsGetCurrentUser(binding, rpcUserInfo);
    }
    RpcExcept(1)
    {
        result = RpcExceptionToResult(RpcExceptionCode());
    }
    RpcEndExcept

    return result;
}

[[nodiscard]] long CallLogin(
    handle_t binding,
    wchar_t* username,
    wchar_t* password,
    PifmsRpcUserInfo* rpcUserInfo
)
{
    long result = pifms::rpc_result::kNetworkError;
    RpcTryExcept
    {
        result = PifmsLogin(binding, username, password, rpcUserInfo);
    }
    RpcExcept(1)
    {
        result = RpcExceptionToResult(RpcExceptionCode());
    }
    RpcEndExcept

    return result;
}

[[nodiscard]] long CallLogout(handle_t binding)
{
    long result = pifms::rpc_result::kNetworkError;
    RpcTryExcept
    {
        result = PifmsLogout(binding);
    }
    RpcExcept(1)
    {
        result = RpcExceptionToResult(RpcExceptionCode());
    }
    RpcEndExcept

    return result;
}

[[nodiscard]] long CallGetLicenseInfo(handle_t binding, PifmsRpcLicenseInfo* rpcLicenseInfo)
{
    long result = pifms::rpc_result::kNetworkError;
    RpcTryExcept
    {
        result = PifmsGetLicenseInfo(binding, rpcLicenseInfo);
    }
    RpcExcept(1)
    {
        result = RpcExceptionToResult(RpcExceptionCode());
    }
    RpcEndExcept

    return result;
}

[[nodiscard]] long CallActivateProduct(
    handle_t binding,
    wchar_t* activationCode,
    PifmsRpcLicenseInfo* rpcLicenseInfo
)
{
    long result = pifms::rpc_result::kNetworkError;
    RpcTryExcept
    {
        result = PifmsActivateProduct(binding, activationCode, rpcLicenseInfo);
    }
    RpcExcept(1)
    {
        result = RpcExceptionToResult(RpcExceptionCode());
    }
    RpcEndExcept

    return result;
}

[[nodiscard]] long CallEnsureAntivirusAvailable(handle_t binding)
{
    long result = pifms::rpc_result::kNetworkError;
    RpcTryExcept
    {
        result = PifmsEnsureAntivirusAvailable(binding);
    }
    RpcExcept(1)
    {
        result = RpcExceptionToResult(RpcExceptionCode());
    }
    RpcEndExcept

    return result;
}

[[nodiscard]] long CallGetAntivirusDatabaseInfo(handle_t binding, PifmsRpcAvDatabaseInfo* rpcDatabaseInfo)
{
    long result = pifms::rpc_result::kNetworkError;
    RpcTryExcept
    {
        result = PifmsGetAntivirusDatabaseInfo(binding, rpcDatabaseInfo);
    }
    RpcExcept(1)
    {
        result = RpcExceptionToResult(RpcExceptionCode());
    }
    RpcEndExcept

    return result;
}

[[nodiscard]] long CallScanFile(handle_t binding, wchar_t* path, PifmsRpcScanResults* rpcResults)
{
    long result = pifms::rpc_result::kNetworkError;
    RpcTryExcept
    {
        result = PifmsScanFile(binding, path, rpcResults);
    }
    RpcExcept(1)
    {
        result = RpcExceptionToResult(RpcExceptionCode());
    }
    RpcEndExcept

    return result;
}

[[nodiscard]] long CallScanDirectory(handle_t binding, wchar_t* path, PifmsRpcScanResults* rpcResults)
{
    long result = pifms::rpc_result::kNetworkError;
    RpcTryExcept
    {
        result = PifmsScanDirectory(binding, path, rpcResults);
    }
    RpcExcept(1)
    {
        result = RpcExceptionToResult(RpcExceptionCode());
    }
    RpcEndExcept

    return result;
}

[[nodiscard]] long CallScanFixedDrives(handle_t binding, PifmsRpcScanResults* rpcResults)
{
    long result = pifms::rpc_result::kNetworkError;
    RpcTryExcept
    {
        result = PifmsScanFixedDrives(binding, rpcResults);
    }
    RpcExcept(1)
    {
        result = RpcExceptionToResult(RpcExceptionCode());
    }
    RpcEndExcept

    return result;
}

[[nodiscard]] long CallConfigureSchedule(
    handle_t binding,
    long targetType,
    wchar_t* path,
    unsigned long intervalMinutes
)
{
    long result = pifms::rpc_result::kNetworkError;
    RpcTryExcept
    {
        result = PifmsConfigureSchedule(binding, targetType, path, intervalMinutes);
    }
    RpcExcept(1)
    {
        result = RpcExceptionToResult(RpcExceptionCode());
    }
    RpcEndExcept

    return result;
}

[[nodiscard]] long CallConfigureMonitoring(handle_t binding, wchar_t* path)
{
    long result = pifms::rpc_result::kNetworkError;
    RpcTryExcept
    {
        result = PifmsConfigureMonitoring(binding, path);
    }
    RpcExcept(1)
    {
        result = RpcExceptionToResult(RpcExceptionCode());
    }
    RpcEndExcept

    return result;
}

[[nodiscard]] long CallGetScheduledScanResults(handle_t binding, PifmsRpcScanResults* rpcResults)
{
    long result = pifms::rpc_result::kNetworkError;
    RpcTryExcept
    {
        result = PifmsGetScheduledScanResults(binding, rpcResults);
    }
    RpcExcept(1)
    {
        result = RpcExceptionToResult(RpcExceptionCode());
    }
    RpcEndExcept

    return result;
}

[[nodiscard]] long CallGetMonitoringScanResults(handle_t binding, PifmsRpcScanResults* rpcResults)
{
    long result = pifms::rpc_result::kNetworkError;
    RpcTryExcept
    {
        result = PifmsGetMonitoringScanResults(binding, rpcResults);
    }
    RpcExcept(1)
    {
        result = RpcExceptionToResult(RpcExceptionCode());
    }
    RpcEndExcept

    return result;
}

[[nodiscard]] bool RequestServiceStop()
{
    RpcBinding binding;
    if (!binding) {
        return false;
    }

    return CallStopService(binding.Get()) == RPC_S_OK;
}

[[nodiscard]] long GetCurrentUser(UserInfo& userInfo)
{
    RpcBinding binding;
    if (!binding) {
        return pifms::rpc_result::kNetworkError;
    }

    PifmsRpcUserInfo rpcUserInfo = {};
    const long result = CallGetCurrentUser(binding.Get(), &rpcUserInfo);
    userInfo = ConvertUserInfo(rpcUserInfo);
    return result;
}

[[nodiscard]] long Login(const std::wstring& username, const std::wstring& password, UserInfo& userInfo)
{
    RpcBinding binding;
    if (!binding) {
        return pifms::rpc_result::kNetworkError;
    }

    PifmsRpcUserInfo rpcUserInfo = {};
    const long result = CallLogin(
        binding.Get(),
        const_cast<wchar_t*>(username.c_str()),
        const_cast<wchar_t*>(password.c_str()),
        &rpcUserInfo
    );
    userInfo = ConvertUserInfo(rpcUserInfo);
    return result;
}

[[nodiscard]] long Logout()
{
    RpcBinding binding;
    if (!binding) {
        return pifms::rpc_result::kNetworkError;
    }

    return CallLogout(binding.Get());
}

[[nodiscard]] long GetLicenseInfo(LicenseInfo& licenseInfo)
{
    RpcBinding binding;
    if (!binding) {
        return pifms::rpc_result::kNetworkError;
    }

    PifmsRpcLicenseInfo rpcLicenseInfo = {};
    const long result = CallGetLicenseInfo(binding.Get(), &rpcLicenseInfo);
    licenseInfo = ConvertLicenseInfo(rpcLicenseInfo);
    return result;
}

[[nodiscard]] long ActivateProduct(const std::wstring& activationCode, LicenseInfo& licenseInfo)
{
    RpcBinding binding;
    if (!binding) {
        return pifms::rpc_result::kNetworkError;
    }

    PifmsRpcLicenseInfo rpcLicenseInfo = {};
    const long result = CallActivateProduct(
        binding.Get(),
        const_cast<wchar_t*>(activationCode.c_str()),
        &rpcLicenseInfo
    );
    licenseInfo = ConvertLicenseInfo(rpcLicenseInfo);
    return result;
}

[[nodiscard]] long EnsureAntivirusAvailable()
{
    RpcBinding binding;
    if (!binding) {
        return pifms::rpc_result::kNetworkError;
    }

    return CallEnsureAntivirusAvailable(binding.Get());
}

[[nodiscard]] long GetAntivirusDatabaseInfo(AntivirusDatabaseInfo& databaseInfo)
{
    RpcBinding binding;
    if (!binding) {
        return pifms::rpc_result::kNetworkError;
    }

    PifmsRpcAvDatabaseInfo rpcDatabaseInfo = {};
    const long result = CallGetAntivirusDatabaseInfo(binding.Get(), &rpcDatabaseInfo);
    databaseInfo = ConvertDatabaseInfo(rpcDatabaseInfo);
    return result;
}

[[nodiscard]] long ScanFile(const std::wstring& path, std::vector<ScanResult>& results)
{
    RpcBinding binding;
    if (!binding) {
        return pifms::rpc_result::kNetworkError;
    }

    PifmsRpcScanResults rpcResults = {};
    const long result = CallScanFile(binding.Get(), const_cast<wchar_t*>(path.c_str()), &rpcResults);
    results = ConvertScanResults(rpcResults);
    return result;
}

[[nodiscard]] long ScanDirectory(const std::wstring& path, std::vector<ScanResult>& results)
{
    RpcBinding binding;
    if (!binding) {
        return pifms::rpc_result::kNetworkError;
    }

    PifmsRpcScanResults rpcResults = {};
    const long result = CallScanDirectory(binding.Get(), const_cast<wchar_t*>(path.c_str()), &rpcResults);
    results = ConvertScanResults(rpcResults);
    return result;
}

[[nodiscard]] long ScanFixedDrives(std::vector<ScanResult>& results)
{
    RpcBinding binding;
    if (!binding) {
        return pifms::rpc_result::kNetworkError;
    }

    PifmsRpcScanResults rpcResults = {};
    const long result = CallScanFixedDrives(binding.Get(), &rpcResults);
    results = ConvertScanResults(rpcResults);
    return result;
}

[[nodiscard]] long ConfigureSchedule(
    ScanTargetType targetType,
    const std::wstring& path,
    std::uint32_t intervalMinutes
)
{
    RpcBinding binding;
    if (!binding) {
        return pifms::rpc_result::kNetworkError;
    }

    return CallConfigureSchedule(
        binding.Get(),
        static_cast<long>(targetType),
        const_cast<wchar_t*>(path.c_str()),
        intervalMinutes
    );
}

[[nodiscard]] long ConfigureMonitoring(const std::wstring& path)
{
    RpcBinding binding;
    if (!binding) {
        return pifms::rpc_result::kNetworkError;
    }

    return CallConfigureMonitoring(binding.Get(), const_cast<wchar_t*>(path.c_str()));
}

[[nodiscard]] long GetScheduledScanResults(std::vector<ScanResult>& results)
{
    RpcBinding binding;
    if (!binding) {
        return pifms::rpc_result::kNetworkError;
    }

    PifmsRpcScanResults rpcResults = {};
    const long result = CallGetScheduledScanResults(binding.Get(), &rpcResults);
    results = ConvertScanResults(rpcResults);
    return result;
}

[[nodiscard]] long GetMonitoringScanResults(std::vector<ScanResult>& results)
{
    RpcBinding binding;
    if (!binding) {
        return pifms::rpc_result::kNetworkError;
    }

    PifmsRpcScanResults rpcResults = {};
    const long result = CallGetMonitoringScanResults(binding.Get(), &rpcResults);
    results = ConvertScanResults(rpcResults);
    return result;
}

[[nodiscard]] std::wstring RpcResultMessage(long result)
{
    switch (result) {
    case pifms::rpc_result::kOk:
        return L"Операция выполнена";
    case pifms::rpc_result::kAuthenticationRequired:
        return L"Требуется вход в учётную запись";
    case pifms::rpc_result::kAuthenticationFailed:
        return L"Неверный логин или пароль";
    case pifms::rpc_result::kNoLicense:
        return L"Активная лицензия отсутствует";
    case pifms::rpc_result::kActivationFailed:
        return L"Не удалось активировать продукт";
    case pifms::rpc_result::kNetworkError:
        return L"Служба или сервер недоступны";
    case pifms::rpc_result::kInvalidServerResponse:
        return L"Сервер вернул некорректный ответ";
    default:
        return L"Внутренняя ошибка службы";
    }
}

}
