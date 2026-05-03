#include "gui/service_guard.h"

#include "common/constants.h"

#include <windows.h>
#include <tlhelp32.h>
#include <winsvc.h>

namespace {

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

[[nodiscard]] bool QueryServiceProcessStatus(SC_HANDLE service, SERVICE_STATUS_PROCESS& status)
{
    DWORD bytesNeeded = 0;
    return QueryServiceStatusEx(
        service,
        SC_STATUS_PROCESS_INFO,
        reinterpret_cast<LPBYTE>(&status),
        sizeof(status),
        &bytesNeeded
    ) == TRUE;
}

[[nodiscard]] bool WaitForServiceRunning(SC_HANDLE service)
{
    for (;;) {
        SERVICE_STATUS_PROCESS status = {};
        if (!QueryServiceProcessStatus(service, status)) {
            return false;
        }

        if (status.dwCurrentState == SERVICE_RUNNING) {
            return true;
        }

        if (status.dwCurrentState != SERVICE_START_PENDING) {
            return false;
        }

        Sleep(500);
    }
}

[[nodiscard]] DWORD GetParentProcessId()
{
    const DWORD currentProcessId = GetCurrentProcessId();
    UniqueHandle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
    if (!snapshot) {
        return 0;
    }

    PROCESSENTRY32W entry = {};
    entry.dwSize = sizeof(entry);

    if (!Process32FirstW(snapshot.Get(), &entry)) {
        return 0;
    }

    do {
        if (entry.th32ProcessID == currentProcessId) {
            return entry.th32ParentProcessID;
        }
    } while (Process32NextW(snapshot.Get(), &entry));

    return 0;
}

[[nodiscard]] DWORD GetServiceProcessId()
{
    ServiceHandle manager(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
    if (!manager) {
        return 0;
    }

    ServiceHandle service(OpenServiceW(manager.Get(), pifms::kServiceName, SERVICE_QUERY_STATUS));
    if (!service) {
        return 0;
    }

    SERVICE_STATUS_PROCESS status = {};
    if (!QueryServiceProcessStatus(service.Get(), status) ||
        status.dwCurrentState != SERVICE_RUNNING) {
        return 0;
    }

    return status.dwProcessId;
}

} 

namespace pifms::gui {

[[nodiscard]] StartupDecision CheckServiceStartup()
{
    ServiceHandle manager(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
    if (!manager) {
        return StartupDecision::Exit;
    }

    ServiceHandle service(OpenServiceW(
        manager.Get(),
        pifms::kServiceName,
        SERVICE_QUERY_STATUS | SERVICE_START
    ));

    if (!service) {
        return StartupDecision::Exit;
    }

    SERVICE_STATUS_PROCESS status = {};
    if (!QueryServiceProcessStatus(service.Get(), status)) {
        return StartupDecision::Exit;
    }

    if (status.dwCurrentState == SERVICE_RUNNING) {
        return StartupDecision::Continue;
    }

    if (status.dwCurrentState == SERVICE_STOPPED) {
        if (!StartServiceW(service.Get(), 0, nullptr) &&
            GetLastError() != ERROR_SERVICE_ALREADY_RUNNING) {
            return StartupDecision::Exit;
        }
    }

    static_cast<void>(WaitForServiceRunning(service.Get()));
    return StartupDecision::Exit;
}

[[nodiscard]] bool IsParentServiceProcess()
{
    const DWORD parentProcessId = GetParentProcessId();
    const DWORD serviceProcessId = GetServiceProcessId();

    return parentProcessId != 0 &&
           serviceProcessId != 0 &&
           parentProcessId == serviceProcessId;
}

}
