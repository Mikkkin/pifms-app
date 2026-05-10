#include "common/text_utils.h"

#include <windows.h>
#include <wincrypt.h>

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <stdexcept>
#include <vector>

namespace {

[[nodiscard]] std::optional<size_t> FindJsonValueStart(const std::string& json, const std::string& key)
{
    const std::string quotedKey = "\"" + key + "\"";
    size_t keyPosition = json.find(quotedKey);
    if (keyPosition == std::string::npos) {
        return std::nullopt;
    }

    size_t colonPosition = json.find(':', keyPosition + quotedKey.size());
    if (colonPosition == std::string::npos) {
        return std::nullopt;
    }

    size_t valuePosition = colonPosition + 1;
    while (valuePosition < json.size() && std::isspace(static_cast<unsigned char>(json[valuePosition])) != 0) {
        ++valuePosition;
    }

    if (valuePosition >= json.size()) {
        return std::nullopt;
    }

    return valuePosition;
}

[[nodiscard]] int HexValue(char value)
{
    if (value >= '0' && value <= '9') {
        return value - '0';
    }
    if (value >= 'a' && value <= 'f') {
        return value - 'a' + 10;
    }
    if (value >= 'A' && value <= 'F') {
        return value - 'A' + 10;
    }
    return -1;
}

[[nodiscard]] std::optional<std::string> ParseJsonStringAt(const std::string& json, size_t position)
{
    if (position >= json.size() || json[position] != '"') {
        return std::nullopt;
    }

    std::string result;
    for (size_t index = position + 1; index < json.size(); ++index) {
        const char ch = json[index];
        if (ch == '"') {
            return result;
        }

        if (ch != '\\') {
            result.push_back(ch);
            continue;
        }

        if (++index >= json.size()) {
            return std::nullopt;
        }

        switch (json[index]) {
        case '"':
        case '\\':
        case '/':
            result.push_back(json[index]);
            break;
        case 'b':
            result.push_back('\b');
            break;
        case 'f':
            result.push_back('\f');
            break;
        case 'n':
            result.push_back('\n');
            break;
        case 'r':
            result.push_back('\r');
            break;
        case 't':
            result.push_back('\t');
            break;
        case 'u':
            if (index + 4 >= json.size()) {
                return std::nullopt;
            } else {
                int codePoint = 0;
                for (size_t offset = 1; offset <= 4; ++offset) {
                    const int hex = HexValue(json[index + offset]);
                    if (hex < 0) {
                        return std::nullopt;
                    }
                    codePoint = (codePoint << 4) | hex;
                }
                index += 4;
                if (codePoint <= 0x7F) {
                    result.push_back(static_cast<char>(codePoint));
                } else if (codePoint <= 0x7FF) {
                    result.push_back(static_cast<char>(0xC0 | (codePoint >> 6)));
                    result.push_back(static_cast<char>(0x80 | (codePoint & 0x3F)));
                } else {
                    result.push_back(static_cast<char>(0xE0 | (codePoint >> 12)));
                    result.push_back(static_cast<char>(0x80 | ((codePoint >> 6) & 0x3F)));
                    result.push_back(static_cast<char>(0x80 | (codePoint & 0x3F)));
                }
            }
            break;
        default:
            return std::nullopt;
        }
    }

    return std::nullopt;
}

[[nodiscard]] std::optional<std::string> Base64UrlDecode(std::string value)
{
    std::replace(value.begin(), value.end(), '-', '+');
    std::replace(value.begin(), value.end(), '_', '/');
    while (value.size() % 4 != 0) {
        value.push_back('=');
    }

    DWORD requiredSize = 0;
    if (!CryptStringToBinaryA(
            value.c_str(),
            static_cast<DWORD>(value.size()),
            CRYPT_STRING_BASE64,
            nullptr,
            &requiredSize,
            nullptr,
            nullptr)) {
        return std::nullopt;
    }

    std::string decoded(requiredSize, '\0');
    if (!CryptStringToBinaryA(
            value.c_str(),
            static_cast<DWORD>(value.size()),
            CRYPT_STRING_BASE64,
            reinterpret_cast<BYTE*>(decoded.data()),
            &requiredSize,
            nullptr,
            nullptr)) {
        return std::nullopt;
    }

    decoded.resize(requiredSize);
    return decoded;
}

[[nodiscard]] std::optional<std::string> ExtractJwtPayload(const std::string& jwt)
{
    const size_t firstSeparator = jwt.find('.');
    if (firstSeparator == std::string::npos) {
        return std::nullopt;
    }

    const size_t secondSeparator = jwt.find('.', firstSeparator + 1);
    if (secondSeparator == std::string::npos) {
        return std::nullopt;
    }

    return Base64UrlDecode(jwt.substr(firstSeparator + 1, secondSeparator - firstSeparator - 1));
}

}

namespace pifms {

[[nodiscard]] std::string WideToUtf8(const std::wstring& value)
{
    if (value.empty()) {
        return {};
    }

    const int requiredSize = WideCharToMultiByte(
        CP_UTF8,
        0,
        value.c_str(),
        static_cast<int>(value.size()),
        nullptr,
        0,
        nullptr,
        nullptr
    );
    if (requiredSize <= 0) {
        return {};
    }

    std::string result(requiredSize, '\0');
    WideCharToMultiByte(
        CP_UTF8,
        0,
        value.c_str(),
        static_cast<int>(value.size()),
        result.data(),
        requiredSize,
        nullptr,
        nullptr
    );
    return result;
}

[[nodiscard]] std::wstring Utf8ToWide(const std::string& value)
{
    if (value.empty()) {
        return {};
    }

    const int requiredSize = MultiByteToWideChar(
        CP_UTF8,
        MB_ERR_INVALID_CHARS,
        value.c_str(),
        static_cast<int>(value.size()),
        nullptr,
        0
    );
    if (requiredSize <= 0) {
        return {};
    }

    std::wstring result(requiredSize, L'\0');
    MultiByteToWideChar(
        CP_UTF8,
        MB_ERR_INVALID_CHARS,
        value.c_str(),
        static_cast<int>(value.size()),
        result.data(),
        requiredSize
    );
    return result;
}

[[nodiscard]] std::string JsonEscape(const std::string& value)
{
    std::string escaped;
    escaped.reserve(value.size() + 8);

    for (const char ch : value) {
        switch (ch) {
        case '"':
            escaped += "\\\"";
            break;
        case '\\':
            escaped += "\\\\";
            break;
        case '\b':
            escaped += "\\b";
            break;
        case '\f':
            escaped += "\\f";
            break;
        case '\n':
            escaped += "\\n";
            break;
        case '\r':
            escaped += "\\r";
            break;
        case '\t':
            escaped += "\\t";
            break;
        default:
            if (static_cast<unsigned char>(ch) < 0x20) {
                char buffer[7] = {};
                sprintf_s(buffer, "\\u%04x", static_cast<unsigned char>(ch));
                escaped += buffer;
            } else {
                escaped.push_back(ch);
            }
            break;
        }
    }

    return escaped;
}

[[nodiscard]] std::optional<std::string> ExtractJsonString(const std::string& json, const std::string& key)
{
    const std::optional<size_t> valuePosition = FindJsonValueStart(json, key);
    if (!valuePosition.has_value()) {
        return std::nullopt;
    }

    return ParseJsonStringAt(json, *valuePosition);
}

[[nodiscard]] std::optional<std::string> ExtractJsonObject(const std::string& json, const std::string& key)
{
    const std::optional<size_t> valuePosition = FindJsonValueStart(json, key);
    if (!valuePosition.has_value() || json[*valuePosition] != '{') {
        return std::nullopt;
    }

    int depth = 0;
    bool inString = false;
    bool escaped = false;

    for (size_t index = *valuePosition; index < json.size(); ++index) {
        const char ch = json[index];
        if (inString) {
            if (escaped) {
                escaped = false;
            } else if (ch == '\\') {
                escaped = true;
            } else if (ch == '"') {
                inString = false;
            }
            continue;
        }

        if (ch == '"') {
            inString = true;
        } else if (ch == '{') {
            ++depth;
        } else if (ch == '}') {
            --depth;
            if (depth == 0) {
                return json.substr(*valuePosition, index - *valuePosition + 1);
            }
        }
    }

    return std::nullopt;
}

[[nodiscard]] std::optional<std::int64_t> ExtractJsonInt64(const std::string& json, const std::string& key)
{
    const std::optional<size_t> valuePosition = FindJsonValueStart(json, key);
    if (!valuePosition.has_value()) {
        return std::nullopt;
    }

    size_t endPosition = *valuePosition;
    if (json[endPosition] == '-') {
        ++endPosition;
    }

    while (endPosition < json.size() && std::isdigit(static_cast<unsigned char>(json[endPosition])) != 0) {
        ++endPosition;
    }

    if (endPosition == *valuePosition) {
        return std::nullopt;
    }

    try {
        return std::stoll(json.substr(*valuePosition, endPosition - *valuePosition));
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

[[nodiscard]] std::optional<bool> ExtractJsonBool(const std::string& json, const std::string& key)
{
    const std::optional<size_t> valuePosition = FindJsonValueStart(json, key);
    if (!valuePosition.has_value()) {
        return std::nullopt;
    }

    if (json.compare(*valuePosition, 4, "true") == 0) {
        return true;
    }
    if (json.compare(*valuePosition, 5, "false") == 0) {
        return false;
    }
    return std::nullopt;
}

[[nodiscard]] std::optional<std::int64_t> ExtractJwtExpiryUnixSeconds(const std::string& jwt)
{
    const std::optional<std::string> payload = ExtractJwtPayload(jwt);
    if (!payload.has_value()) {
        return std::nullopt;
    }

    return ExtractJsonInt64(*payload, "exp");
}

[[nodiscard]] std::optional<std::string> ExtractJwtSubject(const std::string& jwt)
{
    const std::optional<std::string> payload = ExtractJwtPayload(jwt);
    if (!payload.has_value()) {
        return std::nullopt;
    }

    return ExtractJsonString(*payload, "sub");
}

[[nodiscard]] std::optional<std::int64_t> ExtractJwtInt64Claim(const std::string& jwt, const std::string& key)
{
    const std::optional<std::string> payload = ExtractJwtPayload(jwt);
    if (!payload.has_value()) {
        return std::nullopt;
    }

    return ExtractJsonInt64(*payload, key);
}

[[nodiscard]] std::wstring ReadEnvironmentString(const wchar_t* name, const wchar_t* fallbackValue)
{
    DWORD size = GetEnvironmentVariableW(name, nullptr, 0);
    if (size == 0) {
        return fallbackValue;
    }

    std::wstring value(size, L'\0');
    size = GetEnvironmentVariableW(name, value.data(), size);
    if (size == 0) {
        return fallbackValue;
    }

    value.resize(size);
    return value;
}

[[nodiscard]] bool ReadEnvironmentFlag(const wchar_t* name, bool fallbackValue)
{
    const std::wstring value = ReadEnvironmentString(name, fallbackValue ? L"1" : L"0");
    return value == L"1" ||
           value == L"true" ||
           value == L"TRUE" ||
           value == L"yes" ||
           value == L"YES";
}

}
