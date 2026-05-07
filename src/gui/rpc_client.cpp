#include "gui/rpc_client.h"

#include "common/constants.h"

#include <rpc.h>

#include <cstdlib>

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

[[nodiscard]] bool RequestServiceStop()
{
    RPC_WSTR stringBinding = nullptr;
    handle_t binding = nullptr;
    RPC_STATUS status = RpcStringBindingComposeW(
        nullptr,
        reinterpret_cast<RPC_WSTR>(const_cast<wchar_t*>(L"ncalrpc")),
        nullptr,
        reinterpret_cast<RPC_WSTR>(const_cast<wchar_t*>(pifms::kRpcEndpoint)),
        nullptr,
        &stringBinding
    );

    if (status != RPC_S_OK) {
        return false;
    }

    status = RpcBindingFromStringBindingW(stringBinding, &binding);
    RpcStringFreeW(&stringBinding);

    if (status != RPC_S_OK) {
        return false;
    }

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

    RpcBindingFree(&binding);
    return status == RPC_S_OK;
}

}
