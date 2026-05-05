#include "DirectoryMap.h"

#include "EncryptionUtilities.h"
#include "JsonUtils.h"
#include "Utilities.h"

#include <algorithm>
#include <cstring>
#include <fstream>
#include <iterator>
#include <sstream>

std::map<std::wstring, MapEntry>::iterator DirectoryMap::Find(const std::wstring& name)
{
    auto exact = Entries.find(name);
    if (exact != Entries.end())
        return exact;

    for (auto it = Entries.begin(); it != Entries.end(); ++it)
    {
        if (CaseInsensitiveEquals(it->first.c_str(), name.c_str()))
            return it;
    }
    return Entries.end();
}

std::map<std::wstring, MapEntry>::const_iterator DirectoryMap::Find(const std::wstring& name) const
{
    auto exact = Entries.find(name);
    if (exact != Entries.end())
        return exact;

    for (auto it = Entries.begin(); it != Entries.end(); ++it)
    {
        if (CaseInsensitiveEquals(it->first.c_str(), name.c_str()))
            return it;
    }
    return Entries.end();
}

NTSTATUS DirectoryMap::Load(const ObjectStore& store, const std::wstring& dirId, DirectoryMap& map)
{
    map.Entries.clear();
    std::wstring path = store.ExistingMapPath(dirId);
    std::ifstream in(path, std::ios::binary);
    if (!in)
    {
        DWORD attrs = GetFileAttributesW(path.c_str());
        if (attrs != INVALID_FILE_ATTRIBUTES)
            return STATUS_ACCESS_DENIED;
        return Save(store, dirId, map);
    }

    std::stringstream ss;
    ss << in.rdbuf();
    std::string text;
    NTSTATUS decodeStatus = DecodeMapText(dirId, ss.str(), text);
    if (!NT_SUCCESS(decodeStatus))
        return decodeStatus;

    std::istringstream lines(text);
    std::string line;
    while (std::getline(lines, line))
    {
        size_t keyStart = line.find("    \"");
        if (keyStart == std::string::npos)
            continue;

        keyStart = line.find('"', keyStart);
        std::string key = ReadJsonString(line, keyStart);
        size_t idKey = line.find("\"id\"", keyStart + 1);
        size_t typeKey = line.find("\"type\"", keyStart + 1);
        if (idKey == std::string::npos || typeKey == std::string::npos)
            continue;

        size_t idQuote = line.find('"', line.find(':', idKey) + 1);
        size_t typeQuote = line.find('"', line.find(':', typeKey) + 1);
        std::wstring id = JsonUnescapeToWide(ReadJsonString(line, idQuote));
        std::wstring type = JsonUnescapeToWide(ReadJsonString(line, typeQuote));

        MapEntry entry{};
        entry.Id = id;
        entry.Type = type == L"dir" ? ObjectType::Directory : ObjectType::File;
        entry.FileSize = ReadJsonUInt64(line, "size", 0);
        entry.CreationTime = ReadJsonUInt64(line, "ctime", 0);
        entry.LastAccessTime = ReadJsonUInt64(line, "atime", 0);
        entry.LastWriteTime = ReadJsonUInt64(line, "mtime", 0);
        entry.ChangeTime = ReadJsonUInt64(line, "chtime", entry.LastWriteTime);
        entry.FileAttributes = static_cast<UINT32>(ReadJsonUInt64(
            line,
            "attrs",
            entry.Type == ObjectType::Directory ? FILE_ATTRIBUTE_DIRECTORY : FILE_ATTRIBUTE_NORMAL));

        map.Entries[JsonUnescapeToWide(key)] = entry;
    }
    return STATUS_SUCCESS;
}

NTSTATUS DirectoryMap::Save(const ObjectStore& store, const std::wstring& dirId, const DirectoryMap& map)
{
    std::wstring path = store.MapPath(dirId);
    std::wstring legacyPath = store.LegacyMapPath(dirId);
    std::ostringstream text;
    text << "{\n  \"entries\": {\n";
    for (auto it = map.Entries.begin(); it != map.Entries.end(); ++it)
    {
        text << "    \"" << JsonEscape(it->first) << "\": { \"id\": \"" << JsonEscape(it->second.Id)
            << "\", \"type\": \"" << (it->second.Type == ObjectType::Directory ? "dir" : "file")
            << "\", \"size\": " << it->second.FileSize
            << ", \"ctime\": " << it->second.CreationTime
            << ", \"atime\": " << it->second.LastAccessTime
            << ", \"mtime\": " << it->second.LastWriteTime
            << ", \"chtime\": " << it->second.ChangeTime
            << ", \"attrs\": " << it->second.FileAttributes << " }";
        if (std::next(it) != map.Entries.end())
            text << ",";
        text << "\n";
    }
    text << "  }\n}\n";

    std::string plain = text.str();
    std::vector<BYTE> encoded;
    if (!g_MasterKeyReady)
    {
        encoded.assign(plain.begin(), plain.end());
    }
    else
    {
        std::vector<BYTE> encrypted;
        encrypted.reserve(plain.size());
        for (char ch : plain)
            encrypted.push_back(static_cast<BYTE>(ch));

        NTSTATUS status = ApplyContentCipher(g_MasterKey, MapCipherId(dirId), 0, encrypted.data(), static_cast<ULONG>(encrypted.size()));
        if (!NT_SUCCESS(status))
            return status;

        encoded.insert(encoded.end(), EncryptedMapMagic, EncryptedMapMagic + sizeof(EncryptedMapMagic));
        encoded.insert(encoded.end(), encrypted.begin(), encrypted.end());
    }

    NTSTATUS status = WriteAtomicFile(path, encoded);
    if (!NT_SUCCESS(status))
        return status;

    if (legacyPath != path && GetFileAttributesW(legacyPath.c_str()) != INVALID_FILE_ATTRIBUTES)
        DeleteFileW(legacyPath.c_str());
    return STATUS_SUCCESS;
}

NTSTATUS DirectoryMap::WriteAtomicFile(const std::wstring& path, const std::vector<BYTE>& bytes)
{
    std::wstring tmpPath = MakeTempPath(path);
    std::wstring backupPath = path + L".bak";

    NTSTATUS status = WriteFileFullyAndFlush(tmpPath, bytes);
    if (!NT_SUCCESS(status))
        return status;

    if (ReplaceFileW(path.c_str(), tmpPath.c_str(), backupPath.c_str(), REPLACEFILE_WRITE_THROUGH, nullptr, nullptr))
    {
        DeleteFileW(backupPath.c_str());
        return STATUS_SUCCESS;
    }

    DWORD replaceError = GetLastError();
    if (replaceError == ERROR_FILE_NOT_FOUND || replaceError == ERROR_PATH_NOT_FOUND)
    {
        if (MoveFileExW(tmpPath.c_str(), path.c_str(), MOVEFILE_WRITE_THROUGH))
            return STATUS_SUCCESS;
        replaceError = GetLastError();
    }

    DeleteFileW(tmpPath.c_str());
    return Win32ToNtStatus(replaceError);
}

NTSTATUS DirectoryMap::WriteFileFullyAndFlush(const std::wstring& path, const std::vector<BYTE>& bytes)
{
    HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH, nullptr);
    if (h == INVALID_HANDLE_VALUE)
        return Win32ToNtStatus(GetLastError());

    DWORD error = ERROR_SUCCESS;
    size_t done = 0;
    while (done < bytes.size())
    {
        DWORD chunk = static_cast<DWORD>(std::min<size_t>(bytes.size() - done, 1024 * 1024));
        DWORD written = 0;
        if (!WriteFile(h, bytes.data() + done, chunk, &written, nullptr))
        {
            error = GetLastError();
            break;
        }
        if (written == 0)
        {
            error = ERROR_WRITE_FAULT;
            break;
        }
        done += written;
    }

    if (error == ERROR_SUCCESS && !FlushFileBuffers(h))
        error = GetLastError();

    CloseHandle(h);
    if (error != ERROR_SUCCESS)
    {
        DeleteFileW(path.c_str());
        return Win32ToNtStatus(error);
    }
    return STATUS_SUCCESS;
}

std::wstring DirectoryMap::MakeTempPath(const std::wstring& path)
{
    wchar_t suffix[64]{};
    swprintf_s(suffix, L".tmp.%lu.%llu", GetCurrentProcessId(), static_cast<unsigned long long>(GetTickCount64()));
    return path + suffix;
}

NTSTATUS DirectoryMap::DecodeMapText(const std::wstring& dirId, const std::string& raw, std::string& text)
{
    if (raw.size() < sizeof(EncryptedMapMagic) ||
        memcmp(raw.data(), EncryptedMapMagic, sizeof(EncryptedMapMagic)) != 0)
    {
        text = raw;
        return STATUS_SUCCESS;
    }

    std::vector<BYTE> decrypted;
    decrypted.reserve(raw.size() - sizeof(EncryptedMapMagic));
    for (size_t i = sizeof(EncryptedMapMagic); i < raw.size(); ++i)
        decrypted.push_back(static_cast<BYTE>(raw[i]));

    if (!g_MasterKeyReady)
        return STATUS_ACCESS_DENIED;

    NTSTATUS status = ApplyContentCipher(g_MasterKey, MapCipherId(dirId), 0, decrypted.data(), static_cast<ULONG>(decrypted.size()));
    if (!NT_SUCCESS(status))
        return status;

    text.assign(decrypted.begin(), decrypted.end());
    if (text.find("\"entries\"") == std::string::npos)
        return STATUS_ACCESS_DENIED;
    return STATUS_SUCCESS;
}

std::string DirectoryMap::ReadJsonString(const std::string& text, size_t quote)
{
    std::string out;
    for (size_t i = quote + 1; i < text.size(); ++i)
    {
        if (text[i] == '\\' && i + 1 < text.size())
        {
            out += text[i++];
            out += text[i];
        }
        else if (text[i] == '"')
            break;
        else
            out += text[i];
    }
    return out;
}

UINT64 DirectoryMap::ReadJsonUInt64(const std::string& text, const char* key, UINT64 fallback)
{
    std::string token = "\"";
    token += key;
    token += "\"";
    size_t keyPos = text.find(token);
    if (keyPos == std::string::npos)
        return fallback;
    size_t colon = text.find(':', keyPos + token.size());
    if (colon == std::string::npos)
        return fallback;
    size_t start = text.find_first_of("0123456789", colon + 1);
    if (start == std::string::npos)
        return fallback;
    size_t end = start;
    while (end < text.size() && text[end] >= '0' && text[end] <= '9')
        ++end;
    try
    {
        return std::stoull(text.substr(start, end - start));
    }
    catch (...)
    {
        return fallback;
    }
}
