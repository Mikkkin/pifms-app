#pragma once

#include <string>

namespace pifms {

struct DeviceInfo {
    std::string macAddress;
    std::string name;
};

[[nodiscard]] DeviceInfo GetDeviceInfo();

}
