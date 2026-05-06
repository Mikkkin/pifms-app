#include "common/device_info.h"

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>

#include <cstdio>
#include <vector>

namespace {

[[nodiscard]] std::string ReadComputerName()
{
    wchar_t buffer[MAX_COMPUTERNAME_LENGTH + 1] = {};
    DWORD size = ARRAYSIZE(buffer);
    if (!GetComputerNameW(buffer, &size)) {
        return "PIFMS-Windows";
    }

    const int requiredSize = WideCharToMultiByte(
        CP_UTF8,
        0,
        buffer,
        static_cast<int>(size),
        nullptr,
        0,
        nullptr,
        nullptr
    );
    if (requiredSize <= 0) {
        return "PIFMS-Windows";
    }

    std::string result(requiredSize, '\0');
    WideCharToMultiByte(
        CP_UTF8,
        0,
        buffer,
        static_cast<int>(size),
        result.data(),
        requiredSize,
        nullptr,
        nullptr
    );
    return result;
}

[[nodiscard]] std::string FormatMacAddress(const BYTE* address, ULONG length)
{
    if (length < 6) {
        return {};
    }

    char buffer[18] = {};
    sprintf_s(
        buffer,
        "%02X:%02X:%02X:%02X:%02X:%02X",
        address[0],
        address[1],
        address[2],
        address[3],
        address[4],
        address[5]
    );
    return buffer;
}

}

namespace pifms {

[[nodiscard]] DeviceInfo GetDeviceInfo()
{
    ULONG bufferSize = 15 * 1024;
    std::vector<BYTE> buffer(bufferSize);
    IP_ADAPTER_ADDRESSES* adapters = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data());

    DWORD result = GetAdaptersAddresses(
        AF_UNSPEC,
        GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
        nullptr,
        adapters,
        &bufferSize
    );

    if (result == ERROR_BUFFER_OVERFLOW) {
        buffer.resize(bufferSize);
        adapters = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data());
        result = GetAdaptersAddresses(
            AF_UNSPEC,
            GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
            nullptr,
            adapters,
            &bufferSize
        );
    }

    std::string macAddress;
    if (result == NO_ERROR) {
        for (IP_ADAPTER_ADDRESSES* adapter = adapters; adapter != nullptr; adapter = adapter->Next) {
            if (adapter->IfType == IF_TYPE_SOFTWARE_LOOPBACK ||
                adapter->OperStatus != IfOperStatusUp ||
                adapter->PhysicalAddressLength < 6) {
                continue;
            }

            macAddress = FormatMacAddress(adapter->PhysicalAddress, adapter->PhysicalAddressLength);
            if (!macAddress.empty()) {
                break;
            }
        }
    }

    if (macAddress.empty()) {
        macAddress = "00:00:00:00:00:00";
    }

    return DeviceInfo{ macAddress, ReadComputerName() };
}

}
