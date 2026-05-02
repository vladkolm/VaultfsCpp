#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
typedef long NTSTATUS, *PNTSTATUS;
#include <winfsp/winfsp.h>
#include <bcrypt.h>

#include <array>
#include <algorithm>
#include <cstdlib>
#include <cstdio>
#include <cwchar>
#include <cstring>
#include <fstream>
#include <map>
#include <memory>
#include <mutex>
#include <random>
#include <set>
#include <sstream>
#include <string>
#include <vector>

enum class ObjectType
{
    File,
    Directory
};

struct MapEntry
{
    std::wstring Id;
    ObjectType Type = ObjectType::File;
    UINT64 FileSize = 0;
    UINT64 CreationTime = 0;
    UINT64 LastAccessTime = 0;
    UINT64 LastWriteTime = 0;
    UINT64 ChangeTime = 0;
    UINT32 FileAttributes = FILE_ATTRIBUTE_NORMAL;
};

struct ResolvedPath
{
    bool Exists = false;
    std::wstring Id;
    ObjectType Type = ObjectType::Directory;
    std::wstring ParentId;
    std::wstring Name;
    MapEntry Entry;
};

static constexpr wchar_t RootId[] = L"root";
static wchar_t DiskDeviceName[] = L"WinFsp.Disk";
static constexpr UINT64 PhysicalSizeQuantum = 4096;

static UINT32 NormalizeFileAttributes(UINT32 attributes, ObjectType type)
{
    if (attributes == 0 || attributes == INVALID_FILE_ATTRIBUTES)
        return type == ObjectType::Directory ? FILE_ATTRIBUTE_DIRECTORY : FILE_ATTRIBUTE_NORMAL;
    if (type == ObjectType::Directory)
        return attributes | FILE_ATTRIBUTE_DIRECTORY;
    return attributes & ~FILE_ATTRIBUTE_DIRECTORY;
}

static NTSTATUS Win32ToNtStatus(DWORD error)
{
    return FspNtStatusFromWin32(error);
}

static std::wstring TrimTrailingSlash(std::wstring path)
{
    while (path.size() > 3 && (path.back() == L'\\' || path.back() == L'/'))
        path.pop_back();
    return path;
}

static std::string WideToUtf8(const std::wstring& value)
{
    if (value.empty())
        return {};
    int bytes = WideCharToMultiByte(CP_UTF8, 0, value.c_str(), static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
    std::string out(bytes, '\0');
    WideCharToMultiByte(CP_UTF8, 0, value.c_str(), static_cast<int>(value.size()), &out[0], bytes, nullptr, nullptr);
    return out;
}

static std::wstring Utf8ToWide(const std::string& value)
{
    if (value.empty())
        return {};
    int chars = MultiByteToWideChar(CP_UTF8, 0, value.c_str(), static_cast<int>(value.size()), nullptr, 0);
    std::wstring out(chars, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, value.c_str(), static_cast<int>(value.size()), &out[0], chars);
    return out;
}

static std::string JsonEscape(const std::wstring& value)
{
    std::string utf8 = WideToUtf8(value);
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

static std::wstring JsonUnescapeToWide(const std::string& value)
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
    return Utf8ToWide(out);
}

static std::vector<std::wstring> SplitLogicalPath(const std::wstring& path)
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

static std::wstring ParentLogicalPath(const std::wstring& path)
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

static bool IsName(const wchar_t* value, const wchar_t* expected)
{
    return value && expected && 0 == wcscmp(value, expected);
}

static bool CaseInsensitiveEquals(const wchar_t* left, const wchar_t* right)
{
    if (!left || !right)
        return false;
    return CSTR_EQUAL == CompareStringOrdinal(left, -1, right, -1, TRUE);
}

static int CaseInsensitiveCompare(const wchar_t* left, const wchar_t* right)
{
    return CompareStringOrdinal(left ? left : L"", -1, right ? right : L"", -1, TRUE);
}

static bool CaseInsensitiveCharEquals(wchar_t left, wchar_t right)
{
    return CSTR_EQUAL == CompareStringOrdinal(&left, 1, &right, 1, TRUE);
}

static bool WildcardMatch(const wchar_t* pattern, const wchar_t* text)
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

static void CopyDirInfoName(FSP_FSCTL_DIR_INFO* dirInfo, const std::wstring& name)
{
    memcpy(dirInfo->FileNameBuf, name.c_str(), name.size() * sizeof(WCHAR));
}

static size_t DirInfoSizeForName(const std::wstring& name)
{
    return FIELD_OFFSET(FSP_FSCTL_DIR_INFO, FileNameBuf) + name.size() * sizeof(WCHAR);
}

static UINT64 FileTimeToUInt64(const FILETIME& ft)
{
    ULARGE_INTEGER u{};
    u.LowPart = ft.dwLowDateTime;
    u.HighPart = ft.dwHighDateTime;
    return u.QuadPart;
}

static UINT64 CurrentFileTimeUInt64()
{
    FILETIME ft{};
    GetSystemTimeAsFileTime(&ft);
    return FileTimeToUInt64(ft);
}

static UINT64 RoundUp(UINT64 value, UINT64 quantum)
{
    return value == 0 ? 0 : ((value + quantum - 1) / quantum) * quantum;
}

static NTSTATUS BCryptToNtStatus(NTSTATUS status)
{
    return status;
}

static NTSTATUS Sha256(const BYTE* data, ULONG dataSize, std::array<BYTE, 32>& digest)
{
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    DWORD objectLength = 0;
    DWORD resultLength = 0;

    NTSTATUS status = BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
    if (!NT_SUCCESS(status))
        return BCryptToNtStatus(status);

    status = BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&objectLength), sizeof(objectLength), &resultLength, 0);
    if (!NT_SUCCESS(status))
    {
        BCryptCloseAlgorithmProvider(algorithm, 0);
        return BCryptToNtStatus(status);
    }

    std::vector<BYTE> hashObject(objectLength);
    status = BCryptCreateHash(algorithm, &hash, hashObject.data(), objectLength, nullptr, 0, 0);
    if (NT_SUCCESS(status))
        status = BCryptHashData(hash, const_cast<PUCHAR>(data), dataSize, 0);
    if (NT_SUCCESS(status))
        status = BCryptFinishHash(hash, digest.data(), static_cast<ULONG>(digest.size()), 0);

    if (hash)
        BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(algorithm, 0);
    return BCryptToNtStatus(status);
}

static NTSTATUS Sha256(const std::vector<BYTE>& data, std::array<BYTE, 32>& digest)
{
    return Sha256(data.data(), static_cast<ULONG>(data.size()), digest);
}

static std::wstring HexFromBytes(const BYTE* data, size_t size)
{
    static constexpr wchar_t Hex[] = L"0123456789abcdef";
    std::wstring out;
    out.reserve(size * 2);
    for (size_t i = 0; i < size; ++i)
    {
        out.push_back(Hex[(data[i] >> 4) & 0x0f]);
        out.push_back(Hex[data[i] & 0x0f]);
    }
    return out;
}

static NTSTATUS DeriveMasterKey(const std::wstring& passphrase, std::array<BYTE, 32>& key)
{
    std::string utf8 = WideToUtf8(passphrase);
    std::vector<BYTE> material;
    const char prefix[] = "VaultFS Phase2 key v1";
    material.insert(material.end(), prefix, prefix + sizeof(prefix) - 1);
    material.insert(material.end(), utf8.begin(), utf8.end());
    return Sha256(material, key);
}

static void AppendUInt64Le(std::vector<BYTE>& out, UINT64 value)
{
    for (int i = 0; i < 8; ++i)
        out.push_back(static_cast<BYTE>((value >> (i * 8)) & 0xff));
}

static NTSTATUS ApplyContentCipher(const std::array<BYTE, 32>& key, const std::wstring& id, UINT64 offset, BYTE* data, ULONG length)
{
    if (length == 0)
        return STATUS_SUCCESS;

    std::string idUtf8 = WideToUtf8(id);
    ULONG done = 0;
    while (done < length)
    {
        UINT64 absolute = offset + done;
        UINT64 blockIndex = absolute / 32;
        ULONG blockOffset = static_cast<ULONG>(absolute % 32);

        std::vector<BYTE> material;
        const char prefix[] = "VaultFS Phase2 stream v1";
        material.insert(material.end(), prefix, prefix + sizeof(prefix) - 1);
        material.insert(material.end(), key.begin(), key.end());
        material.insert(material.end(), idUtf8.begin(), idUtf8.end());
        AppendUInt64Le(material, blockIndex);

        std::array<BYTE, 32> block{};
        NTSTATUS status = Sha256(material, block);
        if (!NT_SUCCESS(status))
            return status;

        ULONG take = std::min<ULONG>(length - done, static_cast<ULONG>(block.size()) - blockOffset);
        for (ULONG i = 0; i < take; ++i)
            data[done + i] ^= block[blockOffset + i];
        done += take;
    }

    return STATUS_SUCCESS;
}

static std::array<BYTE, 32> g_MasterKey{};
static bool g_MasterKeyReady = false;

static constexpr BYTE EncryptedMapMagic[] = { 'V', 'F', 'S', 'M', 'A', 'P', '2', 0 };

static std::wstring MapCipherId(const std::wstring& dirId)
{
    return L"map:" + dirId;
}

static std::wstring DeriveStorageLabel(const std::wstring& purpose, const std::wstring& id)
{
    if (!g_MasterKeyReady)
        return id;

    std::string purposeUtf8 = WideToUtf8(purpose);
    std::string idUtf8 = WideToUtf8(id);
    std::vector<BYTE> material;
    const char prefix[] = "VaultFS metadata name v1";
    material.insert(material.end(), prefix, prefix + sizeof(prefix) - 1);
    material.insert(material.end(), g_MasterKey.begin(), g_MasterKey.end());
    material.insert(material.end(), purposeUtf8.begin(), purposeUtf8.end());
    material.push_back(0);
    material.insert(material.end(), idUtf8.begin(), idUtf8.end());

    std::array<BYTE, 32> digest{};
    if (!NT_SUCCESS(Sha256(material, digest)))
        return id;
    return HexFromBytes(digest.data(), digest.size());
}

class ObjectStore
{
public:
    explicit ObjectStore(std::wstring root) : root_(std::move(root)) {}

    void Initialize()
    {
        EnsureDirectory(root_);
        EnsureDirectory(ObjectsRoot());
        EnsureDirectory(MapsRoot());
    }

    std::wstring GenerateId() const
    {
        std::random_device rd;
        std::mt19937_64 gen((static_cast<UINT64>(rd()) << 32) ^ rd());
        std::uniform_int_distribution<UINT64> dist;
        UINT64 hi = dist(gen);
        UINT64 lo = dist(gen);

        wchar_t buf[33]{};
        swprintf_s(buf, L"%016llx%016llx", static_cast<unsigned long long>(hi), static_cast<unsigned long long>(lo));
        return buf;
    }

    std::wstring DataPath(const std::wstring& id) const
    {
        std::wstring label = ObjectLabel(id);
        std::wstring path = ObjectsRoot() + L"\\" + label.substr(0, 2);
        path += L"\\";
        path += label.substr(2, 2);
        path += L"\\";
        path += label;
        path += L".data";
        return path;
    }

    std::wstring LegacyDataPath(const std::wstring& id) const
    {
        std::wstring path = ObjectsRoot() + L"\\" + id.substr(0, 2);
        path += L"\\";
        path += id.substr(2, 2);
        path += L"\\";
        path += id;
        path += L".data";
        return path;
    }

    std::wstring ExistingDataPath(const std::wstring& id) const
    {
        std::wstring path = DataPath(id);
        if (GetFileAttributesW(path.c_str()) != INVALID_FILE_ATTRIBUTES)
            return path;
        std::wstring legacy = LegacyDataPath(id);
        if (GetFileAttributesW(legacy.c_str()) != INVALID_FILE_ATTRIBUTES)
            return legacy;
        return path;
    }

    std::wstring MapPath(const std::wstring& dirId) const
    {
        return MapsRoot() + L"\\" + MapLabel(dirId) + L".map";
    }

    std::wstring LegacyMapPath(const std::wstring& dirId) const
    {
        return MapsRoot() + L"\\" + dirId + L".map";
    }

    std::wstring ExistingMapPath(const std::wstring& dirId) const
    {
        std::wstring path = MapPath(dirId);
        if (GetFileAttributesW(path.c_str()) != INVALID_FILE_ATTRIBUTES)
            return path;
        std::wstring legacy = LegacyMapPath(dirId);
        if (GetFileAttributesW(legacy.c_str()) != INVALID_FILE_ATTRIBUTES)
            return legacy;
        return path;
    }

    NTSTATUS CreateFileObject(const std::wstring& id, UINT64 allocationSize)
    {
        NTSTATUS status = EnsureObjectShard(id);
        if (!NT_SUCCESS(status))
            return status;
        std::wstring path = DataPath(id);
        HANDLE h = CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h == INVALID_HANDLE_VALUE)
            return Win32ToNtStatus(GetLastError());
        (void)allocationSize;
        CloseHandle(h);
        return STATUS_SUCCESS;
    }

    NTSTATUS DeleteObject(const std::wstring& id, ObjectType type)
    {
        if (type == ObjectType::File)
        {
            if (!DeleteFileW(ExistingDataPath(id).c_str()))
                return Win32ToNtStatus(GetLastError());
        }
        else if (id != RootId)
        {
            if (!DeleteFileW(ExistingMapPath(id).c_str()))
                return Win32ToNtStatus(GetLastError());
        }
        return STATUS_SUCCESS;
    }

private:
    std::wstring ObjectsRoot() const { return root_ + L"\\.objects"; }
    std::wstring MapsRoot() const { return root_ + L"\\.maps"; }

    static std::wstring ObjectLabel(const std::wstring& id)
    {
        return DeriveStorageLabel(L"object", id);
    }

    static std::wstring MapLabel(const std::wstring& id)
    {
        return DeriveStorageLabel(L"map", id);
    }

    NTSTATUS EnsureObjectShard(const std::wstring& id) const
    {
        std::wstring label = ObjectLabel(id);
        std::wstring a = ObjectsRoot() + L"\\" + label.substr(0, 2);
        std::wstring b = a + L"\\" + label.substr(2, 2);
        NTSTATUS status = EnsureDirectory(a);
        if (!NT_SUCCESS(status))
            return status;
        return EnsureDirectory(b);
    }

    static NTSTATUS EnsureDirectory(const std::wstring& path)
    {
        if (CreateDirectoryW(path.c_str(), nullptr))
            return STATUS_SUCCESS;
        DWORD error = GetLastError();
        if (error == ERROR_ALREADY_EXISTS)
            return STATUS_SUCCESS;
        return Win32ToNtStatus(error);
    }

    std::wstring root_;
};

class DirectoryMap
{
public:
    std::map<std::wstring, MapEntry> Entries;

    std::map<std::wstring, MapEntry>::iterator Find(const std::wstring& name)
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

    std::map<std::wstring, MapEntry>::const_iterator Find(const std::wstring& name) const
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

    static NTSTATUS Load(const ObjectStore& store, const std::wstring& dirId, DirectoryMap& map)
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

    static NTSTATUS Save(const ObjectStore& store, const std::wstring& dirId, const DirectoryMap& map)
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

private:
    static NTSTATUS WriteAtomicFile(const std::wstring& path, const std::vector<BYTE>& bytes)
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

    static NTSTATUS WriteFileFullyAndFlush(const std::wstring& path, const std::vector<BYTE>& bytes)
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

    static std::wstring MakeTempPath(const std::wstring& path)
    {
        wchar_t suffix[64]{};
        swprintf_s(suffix, L".tmp.%lu.%llu", GetCurrentProcessId(), static_cast<unsigned long long>(GetTickCount64()));
        return path + suffix;
    }

    static NTSTATUS DecodeMapText(const std::wstring& dirId, const std::string& raw, std::string& text)
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

    static std::string ReadJsonString(const std::string& text, size_t quote)
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

    static UINT64 ReadJsonUInt64(const std::string& text, const char* key, UINT64 fallback)
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
};

class PathResolver
{
public:
    explicit PathResolver(const ObjectStore& store) : store_(store) {}

    NTSTATUS ResolvePath(const std::wstring& path, ResolvedPath& resolved) const
    {
        auto parts = SplitLogicalPath(path);
        resolved = {};
        resolved.Id = RootId;
        resolved.Type = ObjectType::Directory;
        resolved.Exists = true;
        resolved.Entry.Id = RootId;
        resolved.Entry.Type = ObjectType::Directory;
        resolved.Entry.FileAttributes = FILE_ATTRIBUTE_DIRECTORY;

        if (parts.empty())
            return STATUS_SUCCESS;

        std::wstring current = RootId;
        for (size_t i = 0; i < parts.size(); ++i)
        {
            DirectoryMap map;
            NTSTATUS status = DirectoryMap::Load(store_, current, map);
            if (!NT_SUCCESS(status))
                return status;

            auto it = map.Find(parts[i]);
            if (it == map.Entries.end())
            {
                resolved.Exists = false;
                resolved.ParentId = current;
                resolved.Name = parts[i];
                return i + 1 == parts.size() ? STATUS_SUCCESS : STATUS_OBJECT_NAME_NOT_FOUND;
            }

            resolved.Exists = true;
            resolved.Id = it->second.Id;
            resolved.Type = it->second.Type;
            resolved.ParentId = current;
            resolved.Name = it->first;
            resolved.Entry = it->second;
            current = it->second.Id;

            if (i + 1 < parts.size() && it->second.Type != ObjectType::Directory)
                return STATUS_NOT_A_DIRECTORY;
        }
        return STATUS_SUCCESS;
    }

    NTSTATUS ResolveParent(const std::wstring& path, std::wstring& parentId, std::wstring& name) const
    {
        auto parts = SplitLogicalPath(path);
        if (parts.empty())
            return STATUS_ACCESS_DENIED;

        name = parts.back();
        parts.pop_back();
        std::wstring parentPath;
        for (const auto& part : parts)
        {
            parentPath += L"\\";
            parentPath += part;
        }

        ResolvedPath parent;
        NTSTATUS status = ResolvePath(parentPath, parent);
        if (!NT_SUCCESS(status))
            return status;
        if (!parent.Exists)
            return STATUS_OBJECT_PATH_NOT_FOUND;
        if (parent.Type != ObjectType::Directory)
            return STATUS_NOT_A_DIRECTORY;
        parentId = parent.Id;
        return STATUS_SUCCESS;
    }

private:
    const ObjectStore& store_;
};

struct FileContext
{
    HANDLE Handle = INVALID_HANDLE_VALUE;
    std::wstring Id;
    ObjectType Type = ObjectType::File;
    std::wstring LogicalPath;
    std::wstring ParentId;
    std::wstring Name;
    UINT64 LogicalSize = 0;
    bool DeletePending = false;
    bool LogicalDeleted = false;
    bool PhysicalDeleted = false;
    std::wstring DeletedParentId;
    std::wstring DeletedName;
    MapEntry DeletedEntry;
};

struct VaultContext
{
    std::wstring BackingRoot;
    std::unique_ptr<ObjectStore> Store;
    std::unique_ptr<PathResolver> Resolver;
    std::array<BYTE, 32> MasterKey{};
    std::recursive_mutex MapMutex;
    std::set<FileContext*> LiveContexts;
    std::vector<std::unique_ptr<FileContext>> RetiredContexts;
    FSP_FILE_SYSTEM* FileSystem = nullptr;
};

static VaultContext* g_Vault = nullptr;

static HANDLE g_StopEvent = nullptr;

static BOOL WINAPI ConsoleCtrlHandler(DWORD ctrlType)
{
    switch (ctrlType)
    {
    case CTRL_C_EVENT:
    case CTRL_BREAK_EVENT:
    case CTRL_CLOSE_EVENT:
    case CTRL_SHUTDOWN_EVENT:
        if (g_StopEvent)
            SetEvent(g_StopEvent);
        return TRUE;
    default:
        return FALSE;
    }
}

static void FillFileInfoFromAttributes(const WIN32_FILE_ATTRIBUTE_DATA& data, const std::wstring& id, ObjectType type, FSP_FSCTL_FILE_INFO* info)
{
    memset(info, 0, sizeof(*info));
    info->FileAttributes = type == ObjectType::Directory ? FILE_ATTRIBUTE_DIRECTORY : data.dwFileAttributes;
    info->CreationTime = FileTimeToUInt64(data.ftCreationTime);
    info->LastAccessTime = FileTimeToUInt64(data.ftLastAccessTime);
    info->LastWriteTime = FileTimeToUInt64(data.ftLastWriteTime);
    info->ChangeTime = info->LastWriteTime;

    if (type == ObjectType::File)
    {
        ULARGE_INTEGER size{};
        size.LowPart = data.nFileSizeLow;
        size.HighPart = data.nFileSizeHigh;
        info->FileSize = size.QuadPart;
        info->AllocationSize = ((info->FileSize + 4095) / 4096) * 4096;
    }

    std::hash<std::wstring> h;
    info->IndexNumber = static_cast<UINT64>(h(id));
}

static NTSTATUS GetObjectInfo(const ResolvedPath& resolved, FSP_FSCTL_FILE_INFO* info)
{
    std::wstring path = resolved.Type == ObjectType::File ? g_Vault->Store->ExistingDataPath(resolved.Id) : g_Vault->Store->ExistingMapPath(resolved.Id);
    WIN32_FILE_ATTRIBUTE_DATA data{};
    if (!GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &data))
        return Win32ToNtStatus(GetLastError());

    if (!resolved.ParentId.empty() || resolved.Id == RootId)
    {
        memset(info, 0, sizeof(*info));
        info->FileAttributes = NormalizeFileAttributes(resolved.Entry.FileAttributes, resolved.Type);
        info->CreationTime = resolved.Entry.CreationTime ? resolved.Entry.CreationTime : FileTimeToUInt64(data.ftCreationTime);
        info->LastAccessTime = resolved.Entry.LastAccessTime ? resolved.Entry.LastAccessTime : FileTimeToUInt64(data.ftLastAccessTime);
        info->LastWriteTime = resolved.Entry.LastWriteTime ? resolved.Entry.LastWriteTime : FileTimeToUInt64(data.ftLastWriteTime);
        info->ChangeTime = resolved.Entry.ChangeTime ? resolved.Entry.ChangeTime : info->LastWriteTime;
        if (resolved.Type == ObjectType::File)
        {
            info->FileSize = resolved.Entry.FileSize;
            info->AllocationSize = RoundUp(info->FileSize, PhysicalSizeQuantum);
        }
        std::hash<std::wstring> h;
        info->IndexNumber = static_cast<UINT64>(h(resolved.Id));
        return STATUS_SUCCESS;
    }

    FillFileInfoFromAttributes(data, resolved.Id, resolved.Type, info);
    return STATUS_SUCCESS;
}

static NTSTATUS GetFileInfoByHandle(HANDLE h, const std::wstring& id, ObjectType type, FSP_FSCTL_FILE_INFO* info, UINT64 logicalSize = UINT64_MAX)
{
    if (type == ObjectType::Directory)
    {
        ResolvedPath r{};
        r.Exists = true;
        r.Id = id;
        r.Type = ObjectType::Directory;
        return GetObjectInfo(r, info);
    }

    BY_HANDLE_FILE_INFORMATION bhi{};
    if (!GetFileInformationByHandle(h, &bhi))
        return Win32ToNtStatus(GetLastError());

    memset(info, 0, sizeof(*info));
    info->FileAttributes = bhi.dwFileAttributes;
    info->CreationTime = FileTimeToUInt64(bhi.ftCreationTime);
    info->LastAccessTime = FileTimeToUInt64(bhi.ftLastAccessTime);
    info->LastWriteTime = FileTimeToUInt64(bhi.ftLastWriteTime);
    info->ChangeTime = info->LastWriteTime;

    ULARGE_INTEGER size{};
    size.LowPart = bhi.nFileSizeLow;
    size.HighPart = bhi.nFileSizeHigh;
    info->FileSize = logicalSize == UINT64_MAX ? size.QuadPart : logicalSize;
    info->AllocationSize = ((info->FileSize + 4095) / 4096) * 4096;

    std::hash<std::wstring> hash;
    info->IndexNumber = static_cast<UINT64>(hash(id));
    return STATUS_SUCCESS;
}

static NTSTATUS WriteEncryptedZeros(FileContext* ctx, UINT64 offset, UINT64 length)
{
    static constexpr ULONG ChunkSize = 64 * 1024;
    std::vector<BYTE> chunk(ChunkSize);
    UINT64 done = 0;

    while (done < length)
    {
        ULONG take = static_cast<ULONG>(std::min<UINT64>(ChunkSize, length - done));
        std::fill(chunk.begin(), chunk.begin() + take, static_cast<BYTE>(0));
        NTSTATUS status = ApplyContentCipher(g_Vault->MasterKey, ctx->Id, offset + done, chunk.data(), take);
        if (!NT_SUCCESS(status))
            return status;

        LARGE_INTEGER li{};
        li.QuadPart = static_cast<LONGLONG>(offset + done);
        if (!SetFilePointerEx(ctx->Handle, li, nullptr, FILE_BEGIN))
            return Win32ToNtStatus(GetLastError());

        DWORD written = 0;
        if (!WriteFile(ctx->Handle, chunk.data(), take, &written, nullptr))
            return Win32ToNtStatus(GetLastError());
        if (written != take)
            return STATUS_DISK_FULL;
        done += take;
    }

    return STATUS_SUCCESS;
}

static NTSTATUS SetEncryptedFileSize(FileContext* ctx, UINT64 newSize)
{
    UINT64 oldSize = ctx->LogicalSize;

    if (newSize > oldSize)
    {
        NTSTATUS status = WriteEncryptedZeros(ctx, oldSize, newSize - oldSize);
        if (!NT_SUCCESS(status))
            return status;
    }

    LARGE_INTEGER li{};
    li.QuadPart = static_cast<LONGLONG>(RoundUp(newSize, PhysicalSizeQuantum));
    if (!SetFilePointerEx(ctx->Handle, li, nullptr, FILE_BEGIN) || !SetEndOfFile(ctx->Handle))
        return Win32ToNtStatus(GetLastError());

    return STATUS_SUCCESS;
}

static NTSTATUS SetPhysicalPaddedFileSize(FileContext* ctx, UINT64 logicalSize)
{
    LARGE_INTEGER li{};
    li.QuadPart = static_cast<LONGLONG>(RoundUp(logicalSize, PhysicalSizeQuantum));
    if (!SetFilePointerEx(ctx->Handle, li, nullptr, FILE_BEGIN) || !SetEndOfFile(ctx->Handle))
        return Win32ToNtStatus(GetLastError());
    return STATUS_SUCCESS;
}

static NTSTATUS UpdateEncryptedMapMetadata(FileContext* ctx, UINT64 logicalSize)
{
    if (!ctx || ctx->ParentId.empty() || ctx->Name.empty())
        return STATUS_SUCCESS;

    std::lock_guard<std::recursive_mutex> lock(g_Vault->MapMutex);
    DirectoryMap parent;
    NTSTATUS status = DirectoryMap::Load(*g_Vault->Store, ctx->ParentId, parent);
    if (!NT_SUCCESS(status))
        return status;

    auto it = parent.Find(ctx->Name);
    if (it == parent.Entries.end())
        return STATUS_OBJECT_NAME_NOT_FOUND;

    UINT64 now = CurrentFileTimeUInt64();
    it->second.FileSize = logicalSize;
    if (!it->second.CreationTime)
        it->second.CreationTime = now;
    it->second.LastAccessTime = now;
    it->second.LastWriteTime = now;
    it->second.ChangeTime = now;
    it->second.FileAttributes = ctx->Type == ObjectType::Directory ? FILE_ATTRIBUTE_DIRECTORY : FILE_ATTRIBUTE_NORMAL;
    status = DirectoryMap::Save(*g_Vault->Store, ctx->ParentId, parent);
    if (NT_SUCCESS(status))
        ctx->LogicalSize = logicalSize;
    return status;
}

static NTSTATUS ApiGetVolumeInfo(FSP_FILE_SYSTEM*, FSP_FSCTL_VOLUME_INFO* VolumeInfo)
{
    memset(VolumeInfo, 0, sizeof(*VolumeInfo));
    VolumeInfo->TotalSize = 1024ull * 1024 * 1024 * 1024;
    VolumeInfo->FreeSize = 512ull * 1024 * 1024 * 1024;
    wcscpy_s(VolumeInfo->VolumeLabel, L"VaultFS2");
    return STATUS_SUCCESS;
}

static NTSTATUS ApiGetSecurityByName(FSP_FILE_SYSTEM*, PWSTR FileName, PUINT32 PFileAttributes, PSECURITY_DESCRIPTOR SecurityDescriptor, SIZE_T* PSecurityDescriptorSize)
{
    std::wstring logicalPath = FileName ? FileName : L"";
    std::lock_guard<std::recursive_mutex> lock(g_Vault->MapMutex);
    ResolvedPath resolved;
    NTSTATUS status = g_Vault->Resolver->ResolvePath(logicalPath, resolved);
    if (!NT_SUCCESS(status))
        return status;
    if (!resolved.Exists)
    {
        std::wstring parentId;
        std::wstring name;
        status = g_Vault->Resolver->ResolveParent(logicalPath, parentId, name);
        if (!NT_SUCCESS(status))
            return status;
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }
    if (PFileAttributes)
        *PFileAttributes = resolved.Type == ObjectType::Directory ? FILE_ATTRIBUTE_DIRECTORY : FILE_ATTRIBUTE_NORMAL;
    if (PSecurityDescriptorSize)
        *PSecurityDescriptorSize = 0;
    (void)SecurityDescriptor;
    return STATUS_SUCCESS;
}

static NTSTATUS ApiCreate(FSP_FILE_SYSTEM*, PWSTR FileName, UINT32 CreateOptions, UINT32 GrantedAccess, UINT32 FileAttributes, PSECURITY_DESCRIPTOR, UINT64 AllocationSize, PVOID* PFileContext, FSP_FSCTL_FILE_INFO* FileInfo)
{
    std::wstring logicalPath = FileName ? FileName : L"";

    std::lock_guard<std::recursive_mutex> lock(g_Vault->MapMutex);
    bool isDirectory = 0 != (CreateOptions & FILE_DIRECTORY_FILE);

    ResolvedPath existing;
    NTSTATUS status = g_Vault->Resolver->ResolvePath(logicalPath, existing);
    if (!NT_SUCCESS(status))
        return status;
    if (existing.Exists)
        return STATUS_OBJECT_NAME_COLLISION;

    DirectoryMap parent;
    status = DirectoryMap::Load(*g_Vault->Store, existing.ParentId, parent);
    if (!NT_SUCCESS(status))
        return status;

    std::wstring id = g_Vault->Store->GenerateId();
    if (isDirectory)
    {
        DirectoryMap empty;
        status = DirectoryMap::Save(*g_Vault->Store, id, empty);
    }
    else
    {
        status = g_Vault->Store->CreateFileObject(id, AllocationSize);
    }
    if (!NT_SUCCESS(status))
        return status;

    UINT64 now = CurrentFileTimeUInt64();
    MapEntry newEntry{};
    newEntry.Id = id;
    newEntry.Type = isDirectory ? ObjectType::Directory : ObjectType::File;
    newEntry.FileSize = 0;
    newEntry.CreationTime = now;
    newEntry.LastAccessTime = now;
    newEntry.LastWriteTime = now;
    newEntry.ChangeTime = now;
    newEntry.FileAttributes = NormalizeFileAttributes(FileAttributes, newEntry.Type);
    parent.Entries[existing.Name] = newEntry;
    status = DirectoryMap::Save(*g_Vault->Store, existing.ParentId, parent);
    if (!NT_SUCCESS(status))
        return status;

    auto ctx = std::make_unique<FileContext>();
    ctx->Id = id;
    ctx->Type = isDirectory ? ObjectType::Directory : ObjectType::File;
    ctx->LogicalPath = FileName ? FileName : L"";
    ctx->ParentId = existing.ParentId;
    ctx->Name = existing.Name;
    ctx->LogicalSize = 0;

    if (!isDirectory)
    {
        ctx->Handle = CreateFileW(g_Vault->Store->ExistingDataPath(id).c_str(), GrantedAccess, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (ctx->Handle == INVALID_HANDLE_VALUE)
        {
            status = Win32ToNtStatus(GetLastError());
            return status;
        }
        if (AllocationSize)
        {
            status = SetEncryptedFileSize(ctx.get(), AllocationSize);
            if (!NT_SUCCESS(status))
                return status;
            status = UpdateEncryptedMapMetadata(ctx.get(), AllocationSize);
            if (!NT_SUCCESS(status))
                return status;
        }
    }

    UINT64 logicalSize = ctx->LogicalSize;
    FileContext* rawCtx = ctx.release();
    g_Vault->LiveContexts.insert(rawCtx);
    *PFileContext = rawCtx;
    newEntry.FileSize = logicalSize;
    ResolvedPath created{ true, id, isDirectory ? ObjectType::Directory : ObjectType::File, existing.ParentId, existing.Name, newEntry };
    (void)FileAttributes;
    status = GetObjectInfo(created, FileInfo);
    return status;
}

static NTSTATUS ApiOpen(FSP_FILE_SYSTEM*, PWSTR FileName, UINT32 CreateOptions, UINT32 GrantedAccess, PVOID* PFileContext, FSP_FSCTL_FILE_INFO* FileInfo)
{
    std::wstring logicalPath = FileName ? FileName : L"";

    std::lock_guard<std::recursive_mutex> lock(g_Vault->MapMutex);
    ResolvedPath resolved;
    NTSTATUS status = g_Vault->Resolver->ResolvePath(logicalPath, resolved);
    if (!NT_SUCCESS(status))
        return status;
    if (!resolved.Exists)
        return STATUS_OBJECT_NAME_NOT_FOUND;

    auto ctx = std::make_unique<FileContext>();
    ctx->Id = resolved.Id;
    ctx->Type = resolved.Type;
    ctx->LogicalPath = FileName ? FileName : L"";
    ctx->ParentId = resolved.ParentId;
    ctx->Name = resolved.Name;
    ctx->LogicalSize = resolved.Entry.FileSize;

    if (resolved.Type == ObjectType::File)
    {
        DWORD flags = (CreateOptions & FILE_DELETE_ON_CLOSE) ? FILE_FLAG_DELETE_ON_CLOSE : FILE_ATTRIBUTE_NORMAL;
        ctx->Handle = CreateFileW(g_Vault->Store->ExistingDataPath(resolved.Id).c_str(), GrantedAccess, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, flags, nullptr);
        if (ctx->Handle == INVALID_HANDLE_VALUE)
        {
            status = Win32ToNtStatus(GetLastError());
            return status;
        }
    }

    FileContext* rawCtx = ctx.release();
    g_Vault->LiveContexts.insert(rawCtx);
    *PFileContext = rawCtx;
    status = GetObjectInfo(resolved, FileInfo);
    return status;
}

static NTSTATUS ApiOverwrite(FSP_FILE_SYSTEM*, PVOID FileContext0, UINT32 FileAttributes, BOOLEAN ReplaceFileAttributes, UINT64 AllocationSize, FSP_FSCTL_FILE_INFO* FileInfo)
{
    auto ctx = static_cast<FileContext*>(FileContext0);
    if (!ctx || ctx->Type != ObjectType::File || ctx->Handle == INVALID_HANDLE_VALUE)
        return STATUS_INVALID_HANDLE;

    LARGE_INTEGER zero{};
    if (!SetFilePointerEx(ctx->Handle, zero, nullptr, FILE_BEGIN) || !SetEndOfFile(ctx->Handle))
        return Win32ToNtStatus(GetLastError());
    ctx->LogicalSize = 0;
    if (AllocationSize)
    {
        NTSTATUS status = SetEncryptedFileSize(ctx, AllocationSize);
        if (!NT_SUCCESS(status))
            return status;
    }
    NTSTATUS metadataStatus = UpdateEncryptedMapMetadata(ctx, AllocationSize);
    if (!NT_SUCCESS(metadataStatus))
        return metadataStatus;
    (void)FileAttributes;
    (void)ReplaceFileAttributes;
    return GetFileInfoByHandle(ctx->Handle, ctx->Id, ctx->Type, FileInfo, ctx->LogicalSize);
}

static void ApiCleanup(FSP_FILE_SYSTEM*, PVOID FileContext0, PWSTR FileName, ULONG Flags)
{
    auto ctx = static_cast<FileContext*>(FileContext0);

    bool deleteRequested = 0 != (Flags & FspCleanupDelete);
    if (!deleteRequested && (!ctx || !ctx->DeletePending))
        return;

    if (ctx && ctx->LogicalDeleted)
    {
        if (!ctx->PhysicalDeleted && NT_SUCCESS(g_Vault->Store->DeleteObject(ctx->Id, ctx->Type)))
            ctx->PhysicalDeleted = true;
        return;
    }

    std::lock_guard<std::recursive_mutex> lock(g_Vault->MapMutex);
    ResolvedPath resolved;
    std::wstring logicalPath = FileName && FileName[0] ? FileName : (ctx ? ctx->LogicalPath : L"");
    if (!NT_SUCCESS(g_Vault->Resolver->ResolvePath(logicalPath, resolved)) || !resolved.Exists || resolved.Id == RootId)
        return;

    DirectoryMap parent;
    if (!NT_SUCCESS(DirectoryMap::Load(*g_Vault->Store, resolved.ParentId, parent)))
        return;

    parent.Entries.erase(resolved.Name);
    DirectoryMap::Save(*g_Vault->Store, resolved.ParentId, parent);
    if (ctx)
    {
        ctx->Id = resolved.Id;
        ctx->Type = resolved.Type;
        ctx->DeletedParentId = resolved.ParentId;
        ctx->DeletedName = resolved.Name;
        ctx->DeletedEntry = resolved.Entry;
        ctx->LogicalDeleted = true;
    }
    if (!ctx)
        g_Vault->Store->DeleteObject(resolved.Id, resolved.Type);
}

static void ApiClose(FSP_FILE_SYSTEM*, PVOID FileContext0)
{
    auto ctx = static_cast<FileContext*>(FileContext0);
    if (!ctx)
        return;

    std::lock_guard<std::recursive_mutex> lock(g_Vault->MapMutex);
    auto live = g_Vault->LiveContexts.find(ctx);
    if (live == g_Vault->LiveContexts.end())
        return;
    g_Vault->LiveContexts.erase(live);

    if (ctx->Handle != INVALID_HANDLE_VALUE)
    {
        CloseHandle(ctx->Handle);
        ctx->Handle = INVALID_HANDLE_VALUE;
    }
    if (ctx->LogicalDeleted && !ctx->PhysicalDeleted)
        g_Vault->Store->DeleteObject(ctx->Id, ctx->Type);
    g_Vault->RetiredContexts.emplace_back(ctx);
}

static NTSTATUS ApiRead(FSP_FILE_SYSTEM*, PVOID FileContext0, PVOID Buffer, UINT64 Offset, ULONG Length, PULONG PBytesTransferred)
{
    auto ctx = static_cast<FileContext*>(FileContext0);
    if (!ctx || ctx->Type != ObjectType::File)
        return STATUS_INVALID_HANDLE;
    if (ctx->Handle == INVALID_HANDLE_VALUE)
    {
        *PBytesTransferred = 0;
        return STATUS_SUCCESS;
    }
    if (Offset >= ctx->LogicalSize)
    {
        *PBytesTransferred = 0;
        return STATUS_SUCCESS;
    }
    if (Offset + Length > ctx->LogicalSize)
        Length = static_cast<ULONG>(ctx->LogicalSize - Offset);

    LARGE_INTEGER li{};
    li.QuadPart = static_cast<LONGLONG>(Offset);
    if (!SetFilePointerEx(ctx->Handle, li, nullptr, FILE_BEGIN))
        return Win32ToNtStatus(GetLastError());

    DWORD read = 0;
    if (!ReadFile(ctx->Handle, Buffer, Length, &read, nullptr))
        return Win32ToNtStatus(GetLastError());
    NTSTATUS status = ApplyContentCipher(g_Vault->MasterKey, ctx->Id, Offset, static_cast<BYTE*>(Buffer), read);
    if (!NT_SUCCESS(status))
        return status;
    *PBytesTransferred = read;
    return STATUS_SUCCESS;
}

static NTSTATUS ApiWrite(FSP_FILE_SYSTEM*, PVOID FileContext0, PVOID Buffer, UINT64 Offset, ULONG Length, BOOLEAN WriteToEndOfFile, BOOLEAN ConstrainedIo, PULONG PBytesTransferred, FSP_FSCTL_FILE_INFO* FileInfo)
{
    auto ctx = static_cast<FileContext*>(FileContext0);
    if (!ctx || ctx->Type != ObjectType::File)
        return STATUS_INVALID_HANDLE;

    DWORD moveMethod = FILE_BEGIN;
    LARGE_INTEGER li{};
    li.QuadPart = static_cast<LONGLONG>(WriteToEndOfFile ? ctx->LogicalSize : Offset);
    LARGE_INTEGER writePosition{};
    if (!SetFilePointerEx(ctx->Handle, li, &writePosition, moveMethod))
        return Win32ToNtStatus(GetLastError());
    (void)ConstrainedIo;

    std::vector<BYTE> encrypted(Length);
    memcpy(encrypted.data(), Buffer, Length);
    NTSTATUS status = ApplyContentCipher(g_Vault->MasterKey, ctx->Id, static_cast<UINT64>(writePosition.QuadPart), encrypted.data(), Length);
    if (!NT_SUCCESS(status))
        return status;

    DWORD written = 0;
    if (!WriteFile(ctx->Handle, encrypted.data(), Length, &written, nullptr))
        return Win32ToNtStatus(GetLastError());

    *PBytesTransferred = written;
    UINT64 newLogicalSize = std::max<UINT64>(ctx->LogicalSize, static_cast<UINT64>(writePosition.QuadPart) + written);
    status = SetPhysicalPaddedFileSize(ctx, newLogicalSize);
    if (!NT_SUCCESS(status))
        return status;
    status = UpdateEncryptedMapMetadata(ctx, newLogicalSize);
    if (!NT_SUCCESS(status))
        return status;
    return GetFileInfoByHandle(ctx->Handle, ctx->Id, ctx->Type, FileInfo, ctx->LogicalSize);
}

static NTSTATUS ApiGetFileInfo(FSP_FILE_SYSTEM*, PVOID FileContext0, FSP_FSCTL_FILE_INFO* FileInfo);

static NTSTATUS ApiFlush(FSP_FILE_SYSTEM*, PVOID FileContext0, FSP_FSCTL_FILE_INFO* FileInfo)
{
    auto ctx = static_cast<FileContext*>(FileContext0);
    if (ctx && ctx->Handle == INVALID_HANDLE_VALUE)
        return ApiGetFileInfo(nullptr, FileContext0, FileInfo);
    if (ctx && ctx->Type == ObjectType::File && ctx->Handle != INVALID_HANDLE_VALUE)
    {
        if (!FlushFileBuffers(ctx->Handle))
            return Win32ToNtStatus(GetLastError());
        return GetFileInfoByHandle(ctx->Handle, ctx->Id, ctx->Type, FileInfo, ctx->LogicalSize);
    }
    return STATUS_SUCCESS;
}

static NTSTATUS ApiGetFileInfo(FSP_FILE_SYSTEM*, PVOID FileContext0, FSP_FSCTL_FILE_INFO* FileInfo)
{
    auto ctx = static_cast<FileContext*>(FileContext0);
    if (!ctx)
        return STATUS_INVALID_HANDLE;

    if (ctx->LogicalDeleted)
    {
        memset(FileInfo, 0, sizeof(*FileInfo));
        FileInfo->FileAttributes = ctx->Type == ObjectType::Directory ? FILE_ATTRIBUTE_DIRECTORY : FILE_ATTRIBUTE_NORMAL;
        if (ctx->Type == ObjectType::File)
        {
            FileInfo->FileSize = ctx->LogicalSize;
            FileInfo->AllocationSize = RoundUp(ctx->LogicalSize, PhysicalSizeQuantum);
        }
        std::hash<std::wstring> hash;
        FileInfo->IndexNumber = static_cast<UINT64>(hash(ctx->Id));
        return STATUS_SUCCESS;
    }

    NTSTATUS status = STATUS_SUCCESS;
    if (!ctx->LogicalPath.empty())
    {
        std::lock_guard<std::recursive_mutex> lock(g_Vault->MapMutex);
        ResolvedPath resolved;
        status = g_Vault->Resolver->ResolvePath(ctx->LogicalPath, resolved);
        if (NT_SUCCESS(status) && resolved.Exists)
            status = GetObjectInfo(resolved, FileInfo);
        else
            status = GetFileInfoByHandle(ctx->Handle, ctx->Id, ctx->Type, FileInfo, ctx->LogicalSize);
    }
    else
    {
        status = GetFileInfoByHandle(ctx->Handle, ctx->Id, ctx->Type, FileInfo, ctx->LogicalSize);
    }
    return status;
}

static NTSTATUS ApiSetBasicInfo(FSP_FILE_SYSTEM*, PVOID FileContext0, UINT32 FileAttributes, UINT64 CreationTime, UINT64 LastAccessTime, UINT64 LastWriteTime, UINT64 ChangeTime, FSP_FSCTL_FILE_INFO* FileInfo)
{
    auto ctx = static_cast<FileContext*>(FileContext0);
    if (!ctx)
        return STATUS_INVALID_HANDLE;
    if (ctx->LogicalDeleted)
        return ApiGetFileInfo(nullptr, FileContext0, FileInfo);

    std::lock_guard<std::recursive_mutex> lock(g_Vault->MapMutex);
    if (!ctx->ParentId.empty() && !ctx->Name.empty())
    {
        DirectoryMap parent;
        NTSTATUS status = DirectoryMap::Load(*g_Vault->Store, ctx->ParentId, parent);
        if (!NT_SUCCESS(status))
            return status;
        auto it = parent.Find(ctx->Name);
        if (it == parent.Entries.end())
            return STATUS_OBJECT_NAME_NOT_FOUND;
        if (FileAttributes != 0 && FileAttributes != INVALID_FILE_ATTRIBUTES)
            it->second.FileAttributes = NormalizeFileAttributes(FileAttributes, it->second.Type);
        if (CreationTime)
            it->second.CreationTime = CreationTime;
        if (LastAccessTime)
            it->second.LastAccessTime = LastAccessTime;
        if (LastWriteTime)
            it->second.LastWriteTime = LastWriteTime;
        if (ChangeTime)
            it->second.ChangeTime = ChangeTime;
        status = DirectoryMap::Save(*g_Vault->Store, ctx->ParentId, parent);
        if (!NT_SUCCESS(status))
            return status;
    }

    if (ctx->Type == ObjectType::Directory)
    {
        ResolvedPath resolved;
        NTSTATUS status = g_Vault->Resolver->ResolvePath(ctx->LogicalPath, resolved);
        if (!NT_SUCCESS(status))
            return status;
        return GetObjectInfo(resolved, FileInfo);
    }
    if (ctx->Handle == INVALID_HANDLE_VALUE)
        return ApiGetFileInfo(nullptr, FileContext0, FileInfo);
    return GetFileInfoByHandle(ctx->Handle, ctx->Id, ctx->Type, FileInfo, ctx->LogicalSize);
}

static NTSTATUS ApiSetFileSize(FSP_FILE_SYSTEM*, PVOID FileContext0, UINT64 NewSize, BOOLEAN SetAllocationSize, FSP_FSCTL_FILE_INFO* FileInfo)
{
    auto ctx = static_cast<FileContext*>(FileContext0);
    if (!ctx || ctx->Type != ObjectType::File)
        return STATUS_INVALID_HANDLE;

    NTSTATUS status = SetEncryptedFileSize(ctx, NewSize);
    if (!NT_SUCCESS(status))
        return status;
    status = UpdateEncryptedMapMetadata(ctx, NewSize);
    if (!NT_SUCCESS(status))
        return status;
    (void)SetAllocationSize;
    return GetFileInfoByHandle(ctx->Handle, ctx->Id, ctx->Type, FileInfo, ctx->LogicalSize);
}

static NTSTATUS ApiCanDelete(FSP_FILE_SYSTEM*, PVOID FileContext0, PWSTR FileName)
{
    std::lock_guard<std::recursive_mutex> lock(g_Vault->MapMutex);
    auto ctx = static_cast<FileContext*>(FileContext0);
    std::wstring logicalPath = FileName && FileName[0] ? FileName : (ctx ? ctx->LogicalPath : L"");
    ResolvedPath resolved;
    NTSTATUS status = g_Vault->Resolver->ResolvePath(logicalPath, resolved);
    if (!NT_SUCCESS(status))
        return status;
    if (!resolved.Exists)
        return STATUS_OBJECT_NAME_NOT_FOUND;
    if (resolved.Id == RootId)
        return STATUS_ACCESS_DENIED;

    if (resolved.Type == ObjectType::Directory)
    {
        DirectoryMap map;
        status = DirectoryMap::Load(*g_Vault->Store, resolved.Id, map);
        if (!NT_SUCCESS(status))
            return status;
        if (!map.Entries.empty())
            return STATUS_DIRECTORY_NOT_EMPTY;
    }
    return STATUS_SUCCESS;
}

static NTSTATUS ApiRename(FSP_FILE_SYSTEM*, PVOID FileContext0, PWSTR FileName, PWSTR NewFileName, BOOLEAN ReplaceIfExists)
{
    std::wstring oldPath = FileName ? FileName : L"";
    std::wstring newPath = NewFileName ? NewFileName : L"";

    std::lock_guard<std::recursive_mutex> lock(g_Vault->MapMutex);
    auto ctx = static_cast<FileContext*>(FileContext0);
    ResolvedPath src;
    NTSTATUS status = g_Vault->Resolver->ResolvePath(oldPath, src);
    if ((!NT_SUCCESS(status) || !src.Exists) && ctx && !ctx->LogicalPath.empty())
    {
        oldPath = ctx->LogicalPath;
        status = g_Vault->Resolver->ResolvePath(oldPath, src);
    }
    if (!NT_SUCCESS(status))
        return status;
    if (!src.Exists || src.Id == RootId)
        return STATUS_OBJECT_NAME_NOT_FOUND;

    ResolvedPath dst;
    status = g_Vault->Resolver->ResolvePath(newPath, dst);
    if (!NT_SUCCESS(status))
        return status;
    if (dst.Exists && dst.Id != src.Id && !ReplaceIfExists)
        return STATUS_OBJECT_NAME_COLLISION;

    std::wstring dstParentId, dstName;
    status = g_Vault->Resolver->ResolveParent(newPath, dstParentId, dstName);
    if (!NT_SUCCESS(status))
        return status;

    DirectoryMap srcParent, dstParent;
    status = DirectoryMap::Load(*g_Vault->Store, src.ParentId, srcParent);
    if (!NT_SUCCESS(status))
        return status;
    bool sameParent = src.ParentId == dstParentId;
    if (sameParent)
        dstParent = srcParent;
    else
    {
        status = DirectoryMap::Load(*g_Vault->Store, dstParentId, dstParent);
        if (!NT_SUCCESS(status))
            return status;
    }

    if (dst.Exists)
    {
        if (dst.Id == src.Id)
        {
            dst.Exists = false;
        }
        else
        {
            if (dst.Type == ObjectType::Directory)
            {
                DirectoryMap existingDir;
                status = DirectoryMap::Load(*g_Vault->Store, dst.Id, existingDir);
                if (!NT_SUCCESS(status))
                    return status;
                if (!existingDir.Entries.empty())
                    return STATUS_DIRECTORY_NOT_EMPTY;
            }
            dstParent.Entries.erase(dst.Name);
            if (sameParent)
                srcParent.Entries.erase(dst.Name);
            g_Vault->Store->DeleteObject(dst.Id, dst.Type);
        }
    }

    if (sameParent)
    {
        srcParent.Entries.erase(src.Name);
        MapEntry moved = src.Entry;
        moved.Id = src.Id;
        moved.Type = src.Type;
        srcParent.Entries[dstName] = moved;
        status = DirectoryMap::Save(*g_Vault->Store, src.ParentId, srcParent);
        if (NT_SUCCESS(status) && ctx)
        {
            ctx->LogicalPath = newPath;
            ctx->ParentId = dstParentId;
            ctx->Name = dstName;
        }
        return status;
    }

    MapEntry moved = src.Entry;
    moved.Id = src.Id;
    moved.Type = src.Type;
    dstParent.Entries[dstName] = moved;
    srcParent.Entries.erase(src.Name);

    status = DirectoryMap::Save(*g_Vault->Store, src.ParentId, srcParent);
    if (!NT_SUCCESS(status))
        return status;
    status = DirectoryMap::Save(*g_Vault->Store, dstParentId, dstParent);
    if (NT_SUCCESS(status) && ctx)
    {
        ctx->LogicalPath = newPath;
        ctx->ParentId = dstParentId;
        ctx->Name = dstName;
    }
    return status;
}

static NTSTATUS ApiReadDirectory(FSP_FILE_SYSTEM*, PVOID FileContext0, PWSTR Pattern, PWSTR Marker, PVOID Buffer, ULONG Length, PULONG PBytesTransferred)
{
    auto ctx = static_cast<FileContext*>(FileContext0);
    if (!ctx || ctx->Type != ObjectType::Directory)
        return STATUS_NOT_A_DIRECTORY;

    std::lock_guard<std::recursive_mutex> lock(g_Vault->MapMutex);
    ResolvedPath dir;
    NTSTATUS status = g_Vault->Resolver->ResolvePath(ctx->LogicalPath, dir);
    if (!NT_SUCCESS(status))
        return status;
    if (!dir.Exists)
        return STATUS_OBJECT_NAME_NOT_FOUND;
    if (dir.Type != ObjectType::Directory)
        return STATUS_NOT_A_DIRECTORY;

    DirectoryMap map;
    status = DirectoryMap::Load(*g_Vault->Store, dir.Id, map);
    if (!NT_SUCCESS(status))
        return status;

    ULONG bytes = 0;
    auto addDirEntry = [&](const std::wstring& name, const ResolvedPath& entry) -> bool {
        std::vector<BYTE> dirInfoStorage(DirInfoSizeForName(name) + sizeof(WCHAR));
        FSP_FSCTL_DIR_INFO* dirInfo = reinterpret_cast<FSP_FSCTL_DIR_INFO*>(dirInfoStorage.data());
        memset(dirInfo, 0, dirInfoStorage.size());
        dirInfo->Size = static_cast<UINT16>(DirInfoSizeForName(name));
        NTSTATUS infoStatus = GetObjectInfo(entry, &dirInfo->FileInfo);
        if (!NT_SUCCESS(infoStatus))
            return true;
        CopyDirInfoName(dirInfo, name);
        return !!FspFileSystemAddDirInfo(dirInfo, Buffer, Length, &bytes);
    };

    if (dir.Id != RootId)
    {
        ResolvedPath parent;
        status = g_Vault->Resolver->ResolvePath(ParentLogicalPath(ctx->LogicalPath), parent);
        if (!NT_SUCCESS(status))
            return status;
        if (!parent.Exists || parent.Type != ObjectType::Directory)
            return STATUS_OBJECT_PATH_NOT_FOUND;

        if (!Marker)
        {
            if (!addDirEntry(L".", dir))
            {
                *PBytesTransferred = bytes;
                return STATUS_SUCCESS;
            }
        }
        if (!Marker || IsName(Marker, L"."))
        {
            if (!addDirEntry(L"..", parent))
            {
                *PBytesTransferred = bytes;
                return STATUS_SUCCESS;
            }
            Marker = nullptr;
        }
    }

    for (std::map<std::wstring, MapEntry>::const_iterator it = map.Entries.begin(); it != map.Entries.end(); ++it)
    {
        const std::wstring& name = it->first;
        const MapEntry& entry = it->second;
        if (Marker && CaseInsensitiveCompare(name.c_str(), Marker) <= CSTR_EQUAL)
            continue;
        if (Pattern && !WildcardMatch(Pattern, name.c_str()))
            continue;

        ResolvedPath child{ true, entry.Id, entry.Type, dir.Id, name, entry };
        if (!addDirEntry(name, child))
        {
            *PBytesTransferred = bytes;
            return STATUS_SUCCESS;
        }
    }

    FspFileSystemAddDirInfo(nullptr, Buffer, Length, &bytes);
    *PBytesTransferred = bytes;
    return STATUS_SUCCESS;
}

static NTSTATUS ApiGetDirInfoByName(FSP_FILE_SYSTEM*, PVOID FileContext0, PWSTR FileName, FSP_FSCTL_DIR_INFO* DirInfo)
{
    auto ctx = static_cast<FileContext*>(FileContext0);
    if (!ctx || ctx->Type != ObjectType::Directory)
        return STATUS_NOT_A_DIRECTORY;

    std::lock_guard<std::recursive_mutex> lock(g_Vault->MapMutex);

    ResolvedPath child;
    if (IsName(FileName, L".") || IsName(FileName, L".."))
    {
        std::wstring logicalPath = IsName(FileName, L"..") ? ParentLogicalPath(ctx->LogicalPath) : ctx->LogicalPath;
        NTSTATUS status = g_Vault->Resolver->ResolvePath(logicalPath, child);
        if (!NT_SUCCESS(status))
            return status;
        if (!child.Exists || child.Type != ObjectType::Directory)
            return STATUS_OBJECT_NAME_NOT_FOUND;

        memset(DirInfo, 0, sizeof(*DirInfo));
        DirInfo->Size = static_cast<UINT16>(DirInfoSizeForName(FileName));
        status = GetObjectInfo(child, &DirInfo->FileInfo);
        if (!NT_SUCCESS(status))
            return status;
        CopyDirInfoName(DirInfo, FileName);
        return STATUS_SUCCESS;
    }

    std::wstring childPath;
    if (FileName && (FileName[0] == L'\\' || FileName[0] == L'/'))
    {
        childPath = FileName;
    }
    else if (FileName && !ctx->Name.empty() && CaseInsensitiveEquals(FileName, ctx->Name.c_str()))
    {
        childPath = ctx->LogicalPath;
    }
    else
    {
        childPath = ctx->LogicalPath;
        if (!childPath.empty() && childPath.back() != L'\\')
            childPath += L"\\";
        childPath += FileName ? FileName : L"";
    }

    NTSTATUS status = g_Vault->Resolver->ResolvePath(childPath, child);
    if (!NT_SUCCESS(status))
        return status;
    if (!child.Exists)
        return STATUS_OBJECT_NAME_NOT_FOUND;

    memset(DirInfo, 0, sizeof(*DirInfo));
    DirInfo->Size = static_cast<UINT16>(DirInfoSizeForName(FileName ? FileName : L""));
    status = GetObjectInfo(child, &DirInfo->FileInfo);
    if (!NT_SUCCESS(status))
        return status;
    CopyDirInfoName(DirInfo, FileName);
    return STATUS_SUCCESS;
}

static NTSTATUS ApiSetDelete(FSP_FILE_SYSTEM*, PVOID FileContext0, PWSTR FileName, BOOLEAN DeleteFile)
{
    (void)FileName;
    auto ctx = static_cast<FileContext*>(FileContext0);
    if (!ctx)
        return STATUS_INVALID_HANDLE;

    if (!DeleteFile)
    {
        std::lock_guard<std::recursive_mutex> lock(g_Vault->MapMutex);
        if (ctx->LogicalDeleted && !ctx->DeletedParentId.empty() && !ctx->DeletedName.empty())
        {
            DirectoryMap parent;
            NTSTATUS status = DirectoryMap::Load(*g_Vault->Store, ctx->DeletedParentId, parent);
            if (!NT_SUCCESS(status))
                return status;
            parent.Entries[ctx->DeletedName] = ctx->DeletedEntry;
            status = DirectoryMap::Save(*g_Vault->Store, ctx->DeletedParentId, parent);
            if (!NT_SUCCESS(status))
                return status;
            ctx->LogicalDeleted = false;
            ctx->DeletedParentId.clear();
            ctx->DeletedName.clear();
        }
        ctx->DeletePending = false;
        return STATUS_SUCCESS;
    }

    {
        std::wstring logicalPath = ctx->LogicalPath;
        ResolvedPath resolved;
        NTSTATUS status = g_Vault->Resolver->ResolvePath(logicalPath, resolved);
        if (!NT_SUCCESS(status))
            return status;
        if (!resolved.Exists || resolved.Id == RootId)
            return STATUS_OBJECT_NAME_NOT_FOUND;
        if (resolved.Type == ObjectType::Directory)
        {
            DirectoryMap map;
            status = DirectoryMap::Load(*g_Vault->Store, resolved.Id, map);
            if (!NT_SUCCESS(status))
                return status;
            if (!map.Entries.empty())
                return STATUS_DIRECTORY_NOT_EMPTY;
        }

        DirectoryMap parent;
        status = DirectoryMap::Load(*g_Vault->Store, resolved.ParentId, parent);
        if (!NT_SUCCESS(status))
            return status;
        auto it = parent.Find(resolved.Name);
        if (it == parent.Entries.end())
            return STATUS_OBJECT_NAME_NOT_FOUND;

        ctx->Id = resolved.Id;
        ctx->Type = resolved.Type;
        ctx->DeletedParentId = resolved.ParentId;
        ctx->DeletedName = resolved.Name;
        ctx->DeletedEntry = it->second;
        ctx->LogicalDeleted = true;

        parent.Entries.erase(it);
        status = DirectoryMap::Save(*g_Vault->Store, resolved.ParentId, parent);
        if (!NT_SUCCESS(status))
            return status;
    }

    ctx->DeletePending = true;
    return STATUS_SUCCESS;
}

int wmain(int argc, wchar_t** argv)
{
    if (argc != 3)
    {
        fwprintf(stderr, L"Usage: %s <backing-directory> <mount-point>\n", argv[0]);
        fwprintf(stderr, L"Example: %s D:\\vault_backing X:\n", argv[0]);
        return 2;
    }

    VaultContext vault{};
    vault.BackingRoot = TrimTrailingSlash(argv[1]);
    wchar_t* keyEnv = nullptr;
    size_t keyEnvLength = 0;
    errno_t keyEnvError = _wdupenv_s(&keyEnv, &keyEnvLength, L"VAULTFS_KEY");
    if (keyEnvError != 0 || !keyEnv || keyEnv[0] == L'\0')
    {
        if (keyEnv)
            free(keyEnv);
        fwprintf(stderr, L"VAULTFS_KEY must be set for Phase 2 content encryption.\n");
        return 2;
    }
    NTSTATUS keyStatus = DeriveMasterKey(keyEnv, vault.MasterKey);
    free(keyEnv);
    if (!NT_SUCCESS(keyStatus))
    {
        fwprintf(stderr, L"Failed to derive encryption key: 0x%08X\n", keyStatus);
        return 1;
    }
    g_MasterKey = vault.MasterKey;
    g_MasterKeyReady = true;

    vault.Store = std::make_unique<ObjectStore>(vault.BackingRoot);
    vault.Store->Initialize();
    vault.Resolver = std::make_unique<PathResolver>(*vault.Store);
    g_Vault = &vault;

    g_StopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!g_StopEvent)
    {
        fwprintf(stderr, L"CreateEvent failed: %lu\n", GetLastError());
        return 1;
    }
    if (!SetConsoleCtrlHandler(ConsoleCtrlHandler, TRUE))
    {
        fwprintf(stderr, L"SetConsoleCtrlHandler failed: %lu\n", GetLastError());
        CloseHandle(g_StopEvent);
        g_StopEvent = nullptr;
        return 1;
    }

    DirectoryMap root;
    DirectoryMap::Load(*vault.Store, RootId, root);

    FSP_FSCTL_VOLUME_PARAMS params{};
    params.Version = sizeof(params);
    params.SectorSize = 4096;
    params.SectorsPerAllocationUnit = 1;
    params.VolumeSerialNumber = 0x19831116;
    params.CaseSensitiveSearch = 0;
    params.CasePreservedNames = 1;
    params.UnicodeOnDisk = 1;
    params.PersistentAcls = 0;
    params.PostCleanupWhenModifiedOnly = 1;
    wcscpy_s(params.FileSystemName, L"VaultFS2");

    FSP_FILE_SYSTEM_INTERFACE iface{};
    iface.GetVolumeInfo = ApiGetVolumeInfo;
    iface.GetSecurityByName = ApiGetSecurityByName;
    iface.Create = ApiCreate;
    iface.Open = ApiOpen;
    iface.Overwrite = ApiOverwrite;
    iface.Cleanup = ApiCleanup;
    iface.Close = ApiClose;
    iface.Read = ApiRead;
    iface.Write = ApiWrite;
    iface.Flush = ApiFlush;
    iface.GetFileInfo = ApiGetFileInfo;
    iface.SetBasicInfo = ApiSetBasicInfo;
    iface.SetFileSize = ApiSetFileSize;
    iface.CanDelete = ApiCanDelete;
    iface.SetDelete = ApiSetDelete;
    iface.Rename = ApiRename;
    iface.ReadDirectory = ApiReadDirectory;
    iface.GetDirInfoByName = ApiGetDirInfoByName;

    NTSTATUS status = FspFileSystemCreate(DiskDeviceName, &params, &iface, &vault.FileSystem);
    if (!NT_SUCCESS(status))
    {
        fwprintf(stderr, L"FspFileSystemCreate failed: 0x%08X\n", status);
        SetConsoleCtrlHandler(ConsoleCtrlHandler, FALSE);
        CloseHandle(g_StopEvent);
        g_StopEvent = nullptr;
        return 1;
    }

    vault.FileSystem->UserContext = &vault;
    status = FspFileSystemSetMountPoint(vault.FileSystem, argv[2]);
    if (!NT_SUCCESS(status))
    {
        fwprintf(stderr, L"FspFileSystemSetMountPoint failed: 0x%08X\n", status);
        FspFileSystemDelete(vault.FileSystem);
        SetConsoleCtrlHandler(ConsoleCtrlHandler, FALSE);
        CloseHandle(g_StopEvent);
        g_StopEvent = nullptr;
        return 1;
    }

    status = FspFileSystemStartDispatcher(vault.FileSystem, 0);
    if (!NT_SUCCESS(status))
    {
        fwprintf(stderr, L"FspFileSystemStartDispatcher failed: 0x%08X\n", status);
        FspFileSystemDelete(vault.FileSystem);
        SetConsoleCtrlHandler(ConsoleCtrlHandler, FALSE);
        CloseHandle(g_StopEvent);
        g_StopEvent = nullptr;
        return 1;
    }

    wprintf(L"Mounted %s at %s using short object IDs. Press Ctrl-C to stop.\n", vault.BackingRoot.c_str(), argv[2]);
    WaitForSingleObject(g_StopEvent, INFINITE);

    FspFileSystemStopDispatcher(vault.FileSystem);
    FspFileSystemDelete(vault.FileSystem);
    SetConsoleCtrlHandler(ConsoleCtrlHandler, FALSE);
    CloseHandle(g_StopEvent);
    g_StopEvent = nullptr;
    return 0;
}
