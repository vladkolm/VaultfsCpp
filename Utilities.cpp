#include "Utilities.h"

#include <cwchar>
#include <cstring>

UINT32 NormalizeFileAttributes(UINT32 attributes, ObjectType type)
{
    if (attributes == 0 || attributes == INVALID_FILE_ATTRIBUTES)
        return type == ObjectType::Directory ? FILE_ATTRIBUTE_DIRECTORY : FILE_ATTRIBUTE_NORMAL;
    if (type == ObjectType::Directory)
        return attributes | FILE_ATTRIBUTE_DIRECTORY;
    return attributes & ~FILE_ATTRIBUTE_DIRECTORY;
}

NTSTATUS Win32ToNtStatus(DWORD error)
{
    return FspNtStatusFromWin32(error);
}

std::wstring TrimTrailingSlash(std::wstring path)
{
    while (path.size() > 3 && (path.back() == L'\\' || path.back() == L'/'))
        path.pop_back();
    return path;
}

std::string WideToUtf8(const std::wstring& value)
{
    if (value.empty())
        return {};
    int bytes = WideCharToMultiByte(CP_UTF8, 0, value.c_str(), static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
    std::string out(bytes, '\0');
    WideCharToMultiByte(CP_UTF8, 0, value.c_str(), static_cast<int>(value.size()), &out[0], bytes, nullptr, nullptr);
    return out;
}

std::vector<std::wstring> SplitLogicalPath(const std::wstring& path)
{
    std::vector<std::wstring> parts;
    size_t start = 0;
    while (start < path.size())
    {
        while (start < path.size() && (path[start] == L'\\' || path[start] == L'/'))
            ++start;
        size_t end = start;
        while (end < path.size() && path[end] != L'\\' && path[end] != L'/')
            ++end;
        if (end > start)
            parts.push_back(path.substr(start, end - start));
        start = end;
    }
    return parts;
}

std::wstring ParentLogicalPath(const std::wstring& path)
{
    std::vector<std::wstring> parts = SplitLogicalPath(path);
    if (parts.size() <= 1)
        return L"";

    std::wstring parent;
    for (size_t i = 0; i + 1 < parts.size(); ++i)
    {
        parent += L"\\";
        parent += parts[i];
    }
    return parent;
}

bool IsName(const wchar_t* value, const wchar_t* expected)
{
    return value && expected && 0 == wcscmp(value, expected);
}

bool CaseInsensitiveEquals(const wchar_t* left, const wchar_t* right)
{
    if (!left || !right)
        return false;
    return CSTR_EQUAL == CompareStringOrdinal(left, -1, right, -1, TRUE);
}

int CaseInsensitiveCompare(const wchar_t* left, const wchar_t* right)
{
    return CompareStringOrdinal(left ? left : L"", -1, right ? right : L"", -1, TRUE);
}

bool CaseInsensitiveCharEquals(wchar_t left, wchar_t right)
{
    return CSTR_EQUAL == CompareStringOrdinal(&left, 1, &right, 1, TRUE);
}

bool WildcardMatch(const wchar_t* pattern, const wchar_t* text)
{
    if (pattern == nullptr || pattern[0] == L'\0')
        return true;
    if (*pattern == L'\0')
        return *text == L'\0';
    if (*pattern == L'*')
        return WildcardMatch(pattern + 1, text) || (*text && WildcardMatch(pattern, text + 1));
    if (*pattern == L'?')
        return *text && WildcardMatch(pattern + 1, text + 1);
    return CaseInsensitiveCharEquals(*pattern, *text) && WildcardMatch(pattern + 1, text + 1);
}

void CopyDirInfoName(FSP_FSCTL_DIR_INFO* dirInfo, const std::wstring& name)
{
    memcpy(dirInfo->FileNameBuf, name.c_str(), name.size() * sizeof(WCHAR));
}

size_t DirInfoSizeForName(const std::wstring& name)
{
    return FIELD_OFFSET(FSP_FSCTL_DIR_INFO, FileNameBuf) + name.size() * sizeof(WCHAR);
}

UINT64 FileTimeToUInt64(const FILETIME& ft)
{
    ULARGE_INTEGER u{};
    u.LowPart = ft.dwLowDateTime;
    u.HighPart = ft.dwHighDateTime;
    return u.QuadPart;
}

UINT64 CurrentFileTimeUInt64()
{
    FILETIME ft{};
    GetSystemTimeAsFileTime(&ft);
    return FileTimeToUInt64(ft);
}

UINT64 RoundUp(UINT64 value, UINT64 quantum)
{
    return value == 0 ? 0 : ((value + quantum - 1) / quantum) * quantum;
}

std::string Hex32(UINT32 value)
{
    static const char hex[] = "0123456789ABCDEF";
    std::string out(8, '0');
    for (int i = 7; i >= 0; --i)
    {
        out[i] = hex[value & 0xf];
        value >>= 4;
    }
    return out;
}
