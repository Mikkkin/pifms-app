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
