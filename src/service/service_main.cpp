#include "common/constants.h"

#include <windows.h>
#include <aclapi.h>
#include <rpc.h>
#include <userenv.h>
#include <wtsapi32.h>

#include <algorithm>
#include <cstdlib>
#include <string>
#include <string_view>
#include <vector>

#include "rpc/pifms_control_api.h"

namespace {

struct ChildProcess {
    DWORD sessionId = 0;
    DWORD processId = 0;
    HANDLE process = nullptr;
};

SERVICE_STATUS_HANDLE g_statusHandle = nullptr;
SERVICE_STATUS g_status = {};
CRITICAL_SECTION g_childrenLock = {};
std::vector<ChildProcess> g_children;
LONG g_stopping = 0;

class UniqueHandle {
public:
    explicit UniqueHandle(HANDLE handle = nullptr) noexcept
        : handle_(handle)
    {
    }

    ~UniqueHandle()
    {
        Reset();
    }

    UniqueHandle(const UniqueHandle&) = delete;
    UniqueHandle& operator=(const UniqueHandle&) = delete;

    [[nodiscard]] HANDLE Get() const noexcept
    {
        return handle_;
    }

    [[nodiscard]] explicit operator bool() const noexcept
    {
        return handle_ != nullptr && handle_ != INVALID_HANDLE_VALUE;
    }

    void Reset(HANDLE handle = nullptr) noexcept
    {
        if (handle_ != nullptr && handle_ != INVALID_HANDLE_VALUE) {
            CloseHandle(handle_);
        }

        handle_ = handle;
    }

private:
    HANDLE handle_ = nullptr;
};

class ServiceHandle {
public:
    explicit ServiceHandle(SC_HANDLE handle = nullptr) noexcept
        : handle_(handle)
    {
    }

    ~ServiceHandle()
    {
        if (handle_ != nullptr) {
            CloseServiceHandle(handle_);
        }
    }

    ServiceHandle(const ServiceHandle&) = delete;
    ServiceHandle& operator=(const ServiceHandle&) = delete;

    [[nodiscard]] SC_HANDLE Get() const noexcept
    {
        return handle_;
    }

    [[nodiscard]] explicit operator bool() const noexcept
    {
        return handle_ != nullptr;
    }

private:
    SC_HANDLE handle_ = nullptr;
};

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

void SetServiceStatusState(DWORD state, DWORD win32ExitCode = NO_ERROR)
{
    g_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_status.dwCurrentState = state;
    g_status.dwWin32ExitCode = win32ExitCode;
    g_status.dwControlsAccepted = state == SERVICE_RUNNING ? SERVICE_ACCEPT_SESSIONCHANGE : 0;

    static DWORD checkpoint = 1;
    if (state == SERVICE_START_PENDING || state == SERVICE_STOP_PENDING) {
        g_status.dwCheckPoint = checkpoint++;
        g_status.dwWaitHint = 30000;
    } else {
        g_status.dwCheckPoint = 0;
        g_status.dwWaitHint = 0;
    }

    if (g_statusHandle != nullptr) {
        SetServiceStatus(g_statusHandle, &g_status);
    }
}

[[nodiscard]] std::wstring GetExecutableDirectory()
{
    std::wstring path(MAX_PATH, L'\0');

    for (;;) {
        const DWORD length = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
        if (length == 0) {
            return {};
        }

        if (length < path.size() - 1) {
            path.resize(length);
            break;
        }

        path.resize(path.size() * 2);
    }

    const size_t separator = path.find_last_of(L"\\/");
    if (separator == std::wstring::npos) {
        return {};
    }

    path.resize(separator);
    return path;
}

[[nodiscard]] std::wstring Quote(std::wstring_view value)
{
    std::wstring quoted;
    quoted.reserve(value.size() + 2);
    quoted.push_back(L'"');
    quoted.append(value);
    quoted.push_back(L'"');
    return quoted;
}

void CleanupExitedChildProcessesLocked()
{
    const auto newEnd = std::remove_if(
        g_children.begin(),
        g_children.end(),
        [](ChildProcess& child) {
            if (WaitForSingleObject(child.process, 0) == WAIT_TIMEOUT) {
                return false;
            }

            CloseHandle(child.process);
            child.process = nullptr;
            return true;
        }
    );

    g_children.erase(newEnd, g_children.end());
}

[[nodiscard]] bool HasRunningChildForSessionLocked(DWORD sessionId)
{
    CleanupExitedChildProcessesLocked();

    return std::any_of(
        g_children.begin(),
        g_children.end(),
        [sessionId](const ChildProcess& child) {
            return child.sessionId == sessionId;
        }
    );
}

[[nodiscard]] bool LaunchGuiForSession(DWORD sessionId)
{
    if (sessionId == 0 || InterlockedCompareExchange(&g_stopping, 0, 0) != 0) {
        return false;
    }

    {
        CriticalSectionLock lock(g_childrenLock);
        if (HasRunningChildForSessionLocked(sessionId)) {
            return true;
        }
    }

    HANDLE rawUserToken = nullptr;
    if (!WTSQueryUserToken(sessionId, &rawUserToken)) {
        return false;
    }

    UniqueHandle userToken(rawUserToken);
    HANDLE rawPrimaryToken = nullptr;
    if (!DuplicateTokenEx(
            userToken.Get(),
            MAXIMUM_ALLOWED,
            nullptr,
            SecurityImpersonation,
            TokenPrimary,
            &rawPrimaryToken)) {
        return false;
    }

    UniqueHandle primaryToken(rawPrimaryToken);
    LPVOID environment = nullptr;
    const BOOL hasEnvironment = CreateEnvironmentBlock(&environment, primaryToken.Get(), FALSE);

    const std::wstring directory = GetExecutableDirectory();
    if (directory.empty()) {
        if (hasEnvironment) {
            DestroyEnvironmentBlock(environment);
        }

        return false;
    }

    const std::wstring appPath = directory + L"\\" + pifms::kAppExecutableName;
    std::wstring commandLine = Quote(appPath) + L" " +
        pifms::kServiceChildArg + L" " +
        pifms::kSilentArg;

    STARTUPINFOW startupInfo = {};
    startupInfo.cb = sizeof(startupInfo);
    startupInfo.lpDesktop = const_cast<LPWSTR>(L"winsta0\\default");
    startupInfo.dwFlags = STARTF_USESHOWWINDOW;
    startupInfo.wShowWindow = SW_HIDE;

    PROCESS_INFORMATION processInfo = {};
    const DWORD creationFlags = CREATE_UNICODE_ENVIRONMENT;
    const BOOL created = CreateProcessAsUserW(
        primaryToken.Get(),
        nullptr,
        commandLine.data(),
        nullptr,
        nullptr,
        FALSE,
        creationFlags,
        hasEnvironment ? environment : nullptr,
        directory.c_str(),
        &startupInfo,
        &processInfo
    );

    if (hasEnvironment) {
        DestroyEnvironmentBlock(environment);
    }

    if (!created) {
        return false;
    }

    CloseHandle(processInfo.hThread);

    {
        CriticalSectionLock lock(g_childrenLock);
        g_children.push_back(ChildProcess{
            sessionId,
            processInfo.dwProcessId,
            processInfo.hProcess
        });
    }

    return true;
}

void LaunchGuiForAllUserSessions()
{
    WTS_SESSION_INFOW* sessions = nullptr;
    DWORD sessionCount = 0;

    if (!WTSEnumerateSessionsW(
            WTS_CURRENT_SERVER_HANDLE,
            0,
            1,
            &sessions,
            &sessionCount)) {
        return;
    }

    for (DWORD index = 0; index < sessionCount; ++index) {
        if (sessions[index].SessionId != 0) {
            static_cast<void>(LaunchGuiForSession(sessions[index].SessionId));
        }
    }

    WTSFreeMemory(sessions);
}

void TerminateAllChildProcesses()
{
    std::vector<ChildProcess> children;

    {
        CriticalSectionLock lock(g_childrenLock);
        children.swap(g_children);
    }

    for (const ChildProcess& child : children) {
        if (child.process != nullptr) {
            TerminateProcess(child.process, 0);
            WaitForSingleObject(child.process, 5000);
            CloseHandle(child.process);
        }
    }
}

RPC_STATUS RequestRpcServerStop()
{
    if (InterlockedExchange(&g_stopping, 1) != 0) {
        return RPC_S_OK;
    }

    SetServiceStatusState(SERVICE_STOP_PENDING);
    TerminateAllChildProcesses();

    const RPC_STATUS status = RpcMgmtStopServerListening(nullptr);
    return status == RPC_S_NOT_LISTENING ? RPC_S_OK : status;
}

DWORD WINAPI ServiceControlHandler(DWORD control, DWORD eventType, LPVOID eventData, LPVOID)
{
    if (control != SERVICE_CONTROL_SESSIONCHANGE) {
        return NO_ERROR;
    }

    if (eventType != WTS_SESSION_LOGON &&
        eventType != WTS_CONSOLE_CONNECT &&
        eventType != WTS_REMOTE_CONNECT) {
        return NO_ERROR;
    }

    const auto* notification = static_cast<WTSSESSION_NOTIFICATION*>(eventData);
    if (notification != nullptr && notification->dwSessionId != 0) {
        static_cast<void>(LaunchGuiForSession(notification->dwSessionId));
    }

    return NO_ERROR;
}

[[nodiscard]] RPC_STATUS StartRpcServer()
{
    RPC_STATUS status = RpcServerUseProtseqEpW(
        reinterpret_cast<RPC_WSTR>(const_cast<wchar_t*>(L"ncalrpc")),
        RPC_C_PROTSEQ_MAX_REQS_DEFAULT,
        reinterpret_cast<RPC_WSTR>(const_cast<wchar_t*>(pifms::kRpcEndpoint)),
        nullptr
    );

    if (status != RPC_S_OK && status != RPC_S_DUPLICATE_ENDPOINT) {
        return status;
    }

    status = RpcServerRegisterIfEx(
        PIFMSControl_v1_0_s_ifspec,
        nullptr,
        nullptr,
        RPC_IF_ALLOW_LOCAL_ONLY,
        RPC_C_LISTEN_MAX_CALLS_DEFAULT,
        nullptr
    );

    if (status != RPC_S_OK) {
        return status;
    }

    return RPC_S_OK;
}

void WINAPI ServiceMain(DWORD, LPWSTR*)
{
    g_statusHandle = RegisterServiceCtrlHandlerExW(
        pifms::kServiceName,
        ServiceControlHandler,
        nullptr
    );

    if (g_statusHandle == nullptr) {
        return;
    }

    InitializeCriticalSection(&g_childrenLock);
    SetServiceStatusState(SERVICE_START_PENDING);

    const RPC_STATUS rpcStatus = StartRpcServer();
    if (rpcStatus != RPC_S_OK) {
        SetServiceStatusState(SERVICE_STOPPED, rpcStatus);
        DeleteCriticalSection(&g_childrenLock);
        return;
    }

    SetServiceStatusState(SERVICE_RUNNING);
    LaunchGuiForAllUserSessions();

    const RPC_STATUS listenStatus = RpcServerListen(
        1,
        RPC_C_LISTEN_MAX_CALLS_DEFAULT,
        FALSE
    );

    SetServiceStatusState(SERVICE_STOP_PENDING);
    TerminateAllChildProcesses();
    RpcServerUnregisterIf(PIFMSControl_v1_0_s_ifspec, nullptr, FALSE);

    SetServiceStatusState(
        SERVICE_STOPPED,
        listenStatus == RPC_S_OK || listenStatus == RPC_S_ALREADY_LISTENING ? NO_ERROR : listenStatus
    );

    DeleteCriticalSection(&g_childrenLock);
}

[[nodiscard]] bool CommandLineContains(std::wstring_view commandLine, std::wstring_view argument)
{
    return commandLine.find(argument) != std::wstring_view::npos;
}

[[nodiscard]] bool GrantAuthenticatedUsersServiceStart(SC_HANDLE service)
{
    PACL oldDacl = nullptr;
    PSECURITY_DESCRIPTOR securityDescriptor = nullptr;

    DWORD result = GetSecurityInfo(
        service,
        SE_SERVICE,
        DACL_SECURITY_INFORMATION,
        nullptr,
        nullptr,
        &oldDacl,
        nullptr,
        &securityDescriptor
    );

    if (result != ERROR_SUCCESS) {
        return false;
    }

    BYTE authenticatedUsersSidBuffer[SECURITY_MAX_SID_SIZE] = {};
    PSID authenticatedUsersSid = authenticatedUsersSidBuffer;
    DWORD authenticatedUsersSidSize = sizeof(authenticatedUsersSidBuffer);
    if (!CreateWellKnownSid(
            WinAuthenticatedUserSid,
            nullptr,
            authenticatedUsersSid,
            &authenticatedUsersSidSize)) {
        LocalFree(securityDescriptor);
        return false;
    }

    EXPLICIT_ACCESSW access = {};
    access.grfAccessPermissions =
        SERVICE_QUERY_CONFIG |
        SERVICE_QUERY_STATUS |
        SERVICE_START |
        SERVICE_INTERROGATE |
        READ_CONTROL;
    access.grfAccessMode = GRANT_ACCESS;
    access.grfInheritance = NO_INHERITANCE;
    access.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    access.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
    access.Trustee.ptstrName = reinterpret_cast<LPWSTR>(authenticatedUsersSid);

    PACL newDacl = nullptr;
    result = SetEntriesInAclW(1, &access, oldDacl, &newDacl);
    if (result == ERROR_SUCCESS) {
        result = SetSecurityInfo(
            service,
            SE_SERVICE,
            DACL_SECURITY_INFORMATION,
            nullptr,
            nullptr,
            newDacl,
            nullptr
        );
    }

    if (newDacl != nullptr) {
        LocalFree(newDacl);
    }

    if (securityDescriptor != nullptr) {
        LocalFree(securityDescriptor);
    }

    return result == ERROR_SUCCESS;
}

int InstallService()
{
    const std::wstring directory = GetExecutableDirectory();
    if (directory.empty()) {
        return 1;
    }

    const std::wstring servicePath = directory + L"\\PIFMSService.exe";
    const std::wstring quotedServicePath = Quote(servicePath);

    ServiceHandle manager(OpenSCManagerW(
        nullptr,
        nullptr,
        SC_MANAGER_CREATE_SERVICE | SC_MANAGER_CONNECT
    ));
    if (!manager) {
        return 1;
    }

    ServiceHandle service(CreateServiceW(
        manager.Get(),
        pifms::kServiceName,
        pifms::kServiceDisplayName,
        SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS,
        SERVICE_AUTO_START,
        SERVICE_ERROR_NORMAL,
        quotedServicePath.c_str(),
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr
    ));

    if (!service) {
        if (GetLastError() != ERROR_SERVICE_EXISTS) {
            return 1;
        }

        ServiceHandle existing(OpenServiceW(
            manager.Get(),
            pifms::kServiceName,
            SERVICE_CHANGE_CONFIG | READ_CONTROL | WRITE_DAC
        ));

        if (!existing) {
            return 1;
        }

        if (!ChangeServiceConfigW(
                existing.Get(),
                SERVICE_WIN32_OWN_PROCESS,
                SERVICE_AUTO_START,
                SERVICE_ERROR_NORMAL,
                quotedServicePath.c_str(),
                nullptr,
                nullptr,
                nullptr,
                nullptr,
                nullptr,
                pifms::kServiceDisplayName)) {
            return 1;
        }

        static_cast<void>(GrantAuthenticatedUsersServiceStart(existing.Get()));
        return 0;
    }

    static_cast<void>(GrantAuthenticatedUsersServiceStart(service.Get()));
    return 0;
}

int UninstallService()
{
    ServiceHandle manager(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
    if (!manager) {
        return 1;
    }

    ServiceHandle service(OpenServiceW(manager.Get(), pifms::kServiceName, DELETE));
    if (!service) {
        return 1;
    }

    return DeleteService(service.Get()) ? 0 : 1;
}

int RunService()
{
    SERVICE_TABLE_ENTRYW serviceTable[] = {
        { const_cast<LPWSTR>(pifms::kServiceName), ServiceMain },
        { nullptr, nullptr }
    };

    return StartServiceCtrlDispatcherW(serviceTable) ? 0 : 1;
}

} 

extern "C" void* __RPC_USER midl_user_allocate(size_t size)
{
    return std::malloc(size);
}

extern "C" void __RPC_USER midl_user_free(void* pointer)
{
    std::free(pointer);
}

extern "C" void PifmsStopService(handle_t)
{
    static_cast<void>(RequestRpcServerStop());
}

int WINAPI wWinMain(HINSTANCE, HINSTANCE, LPWSTR commandLine, int)
{
    const std::wstring_view commandLineView = commandLine != nullptr ? commandLine : L"";

    if (CommandLineContains(commandLineView, L"/install")) {
        return InstallService();
    }

    if (CommandLineContains(commandLineView, L"/uninstall")) {
        return UninstallService();
    }

    return RunService();
}
