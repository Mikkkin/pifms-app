#pragma once

#include <cstdint>
#include <optional>
#include <string>

namespace pifms {

[[nodiscard]] std::string WideToUtf8(const std::wstring& value);
[[nodiscard]] std::wstring Utf8ToWide(const std::string& value);
[[nodiscard]] std::string JsonEscape(const std::string& value);
[[nodiscard]] std::optional<std::string> ExtractJsonString(const std::string& json, const std::string& key);
[[nodiscard]] std::optional<std::string> ExtractJsonObject(const std::string& json, const std::string& key);
[[nodiscard]] std::optional<std::int64_t> ExtractJsonInt64(const std::string& json, const std::string& key);
[[nodiscard]] std::optional<bool> ExtractJsonBool(const std::string& json, const std::string& key);
[[nodiscard]] std::optional<std::int64_t> ExtractJwtExpiryUnixSeconds(const std::string& jwt);
[[nodiscard]] std::optional<std::string> ExtractJwtSubject(const std::string& jwt);
[[nodiscard]] std::optional<std::int64_t> ExtractJwtInt64Claim(const std::string& jwt, const std::string& key);
[[nodiscard]] std::wstring ReadEnvironmentString(const wchar_t* name, const wchar_t* fallbackValue);
[[nodiscard]] bool ReadEnvironmentFlag(const wchar_t* name, bool fallbackValue);

}
