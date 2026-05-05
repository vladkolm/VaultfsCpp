#include "JsonUtils.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

namespace
{
    std::string WideToUtf8ForJson(const std::wstring& value)
    {
        if (value.empty())
            return {};
        int bytes = WideCharToMultiByte(CP_UTF8, 0, value.c_str(), static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
        std::string out(bytes, '\0');
        WideCharToMultiByte(CP_UTF8, 0, value.c_str(), static_cast<int>(value.size()), &out[0], bytes, nullptr, nullptr);
        return out;
    }

    std::wstring Utf8ToWideForJson(const std::string& value)
    {
        if (value.empty())
            return {};
        int chars = MultiByteToWideChar(CP_UTF8, 0, value.c_str(), static_cast<int>(value.size()), nullptr, 0);
        std::wstring out(chars, L'\0');
        MultiByteToWideChar(CP_UTF8, 0, value.c_str(), static_cast<int>(value.size()), &out[0], chars);
        return out;
    }
}

std::string JsonEscape(const std::wstring& value)
{
    std::string utf8 = WideToUtf8ForJson(value);
    std::string out;
    for (char ch : utf8)
    {
        switch (ch)
        {
        case '\\': out += "\\\\"; break;
        case '"': out += "\\\""; break;
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
        default: out += ch; break;
        }
    }
    return out;
}

std::wstring JsonUnescapeToWide(const std::string& value)
{
    std::string out;
    for (size_t i = 0; i < value.size(); ++i)
    {
        if (value[i] == '\\' && i + 1 < value.size())
        {
            char n = value[++i];
            if (n == 'n') out += '\n';
            else if (n == 'r') out += '\r';
            else if (n == 't') out += '\t';
            else out += n;
        }
        else
            out += value[i];
    }
    return Utf8ToWideForJson(out);
}
