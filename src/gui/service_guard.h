#pragma once

namespace pifms::gui {

enum class StartupDecision {
    Continue,
    Exit
};

[[nodiscard]] StartupDecision CheckServiceStartup();
[[nodiscard]] bool IsParentServiceProcess();

}
