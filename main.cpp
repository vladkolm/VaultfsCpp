#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
typedef long NTSTATUS, *PNTSTATUS;
#include <winfsp/winfsp.h>
#include <bcrypt.h>
#include "Data.h"
#include "JsonUtils.h"
#include "Utilities.h"
#include "ObjectStore.h"
#include "DirectoryMap.h"
#include "PathResolver.h"
#include "FileOperation.h"

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

static constexpr wchar_t RootId[] = L"root";
static wchar_t DiskDeviceName[] = L"WinFsp.Disk";
static constexpr UINT64 PhysicalSizeQuantum = 4096;

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

static bool g_MasterKeyReady = false;

static NTSTATUS ApplyContentCipher(const std::array<BYTE, 32>& key, const std::wstring& id, UINT64 offset, BYTE* data, ULONG length)
{
    if (!g_MasterKeyReady)
        return STATUS_SUCCESS;
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


// Utilities are consumed by the extracted implementation files below.
#include "Utilities.cpp"


// ObjectStore uses the internal encryption/path helpers above.
#include "ObjectStore.cpp"


// JsonUtils is consumed by DirectoryMap in this unity-style build.
#include "JsonUtils.cpp"


// DirectoryMap uses the internal JSON/encryption helpers above.
#include "DirectoryMap.cpp"


// PathResolver uses the internal path helpers above.
#include "PathResolver.cpp"

static VaultContext* g_Vault = nullptr;

static HANDLE g_StopEvent = nullptr;

static std::wstring CurrentProcessImageName(UINT32 pid)
{
    if (!pid)
        return L"";

    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!process)
        return L"";

    wchar_t path[MAX_PATH]{};
    DWORD size = static_cast<DWORD>(_countof(path));
    std::wstring name;
    if (QueryFullProcessImageNameW(process, 0, path, &size))
    {
        name.assign(path, size);
        size_t slash = name.find_last_of(L"\\/");
        if (slash != std::wstring::npos)
            name.erase(0, slash + 1);
    }
    CloseHandle(process);
    return name;
}

static void TraceEvent(const char* operation, const std::wstring& path, const std::string& detail)
{
    if (!g_Vault || g_Vault->TracePath.empty())
        return;

    UINT32 pid = 0;
    try
    {
        pid = FspFileSystemOperationProcessId();
    }
    catch (...)
    {
        pid = 0;
    }

    SYSTEMTIME now{};
    GetLocalTime(&now);

    std::ostringstream line;
    line << now.wYear << '-';
    if (now.wMonth < 10) line << '0';
    line << now.wMonth << '-';
    if (now.wDay < 10) line << '0';
    line << now.wDay << ' ';
    if (now.wHour < 10) line << '0';
    line << now.wHour << ':';
    if (now.wMinute < 10) line << '0';
    line << now.wMinute << ':';
    if (now.wSecond < 10) line << '0';
    line << now.wSecond << '.';
    if (now.wMilliseconds < 100) line << '0';
    if (now.wMilliseconds < 10) line << '0';
    line << now.wMilliseconds;
    line << " pid=" << pid;
    std::wstring image = CurrentProcessImageName(pid);
    if (!image.empty())
        line << " proc=" << WideToUtf8(image);
    line << " op=" << operation;
    if (!path.empty())
        line << " path=" << WideToUtf8(path);
    if (!detail.empty())
        line << ' ' << detail;
    line << "\r\n";

    std::lock_guard<std::mutex> lock(g_Vault->TraceMutex);
    std::ofstream out(g_Vault->TracePath, std::ios::binary | std::ios::app);
    if (out)
        out << line.str();
}

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


// FileOperation uses the internal store/map/resolver types above.
#include "FileOperation.cpp"

int wmain(int argc, wchar_t** argv)
{
    bool noEncryption = false;
    std::vector<std::wstring> positional;
    for (int i = 1; i < argc; ++i)
    {
        if (CaseInsensitiveEquals(argv[i], L"--NoEncryption"))
        {
            noEncryption = true;
        }
        else if (argv[i] && argv[i][0] == L'-')
        {
            fwprintf(stderr, L"Unknown option: %s\n", argv[i]);
            fwprintf(stderr, L"Usage: %s [--NoEncryption] <backing-directory> <mount-point>\n", argv[0]);
            fwprintf(stderr, L"Example: %s D:\\vault_backing X:\n", argv[0]);
            fwprintf(stderr, L"Example: %s --NoEncryption D:\\vault_backing X:\n", argv[0]);
            return 2;
        }
        else
        {
            positional.push_back(argv[i] ? argv[i] : L"");
        }
    }

    if (positional.size() != 2)
    {
        fwprintf(stderr, L"Usage: %s [--NoEncryption] <backing-directory> <mount-point>\n", argv[0]);
        fwprintf(stderr, L"Example: %s D:\\vault_backing X:\n", argv[0]);
        fwprintf(stderr, L"Example: %s --NoEncryption D:\\vault_backing X:\n", argv[0]);
        return 2;
    }

    VaultContext vault{};
    vault.BackingRoot = TrimTrailingSlash(positional[0]);
    if (noEncryption)
    {
        g_MasterKey = {};
        g_MasterKeyReady = false;
    }
    else
    {
        wchar_t* keyEnv = nullptr;
        size_t keyEnvLength = 0;
        errno_t keyEnvError = _wdupenv_s(&keyEnv, &keyEnvLength, L"VAULTFS_KEY");
        if (keyEnvError != 0 || !keyEnv || keyEnv[0] == L'\0')
        {
            if (keyEnv)
                free(keyEnv);
            fwprintf(stderr, L"VAULTFS_KEY must be set unless --NoEncryption is used.\n");
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
    }

    wchar_t* traceEnv = nullptr;
    size_t traceEnvLength = 0;
    if (0 == _wdupenv_s(&traceEnv, &traceEnvLength, L"VAULTFS_TRACE") && traceEnv && traceEnv[0] != L'\0')
        vault.TracePath = traceEnv;
    if (traceEnv)
        free(traceEnv);

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
    params.FileInfoTimeout = 0;
    params.DirInfoTimeoutValid = 1;
    params.DirInfoTimeout = 0;
    params.CaseSensitiveSearch = 0;
    params.CasePreservedNames = 1;
    params.UnicodeOnDisk = 1;
    params.PersistentAcls = 0;
    params.PostCleanupWhenModifiedOnly = 1;
    params.PassQueryDirectoryFileName = 1;
    params.FlushAndPurgeOnCleanup = 1;
    wcscpy_s(params.FileSystemName, L"VaultFS2");

    FSP_FILE_SYSTEM_INTERFACE iface{};
    FileOperation::Register(iface);

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
    status = FspFileSystemSetMountPoint(vault.FileSystem, const_cast<PWSTR>(positional[1].c_str()));
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

    wprintf(L"Mounted %s at %s using short object IDs (%s). Press Ctrl-C to stop.\n",
        vault.BackingRoot.c_str(),
        positional[1].c_str(),
        noEncryption ? L"no encryption" : L"encrypted");
    WaitForSingleObject(g_StopEvent, INFINITE);

    FspFileSystemStopDispatcher(vault.FileSystem);
    FspFileSystemDelete(vault.FileSystem);
    SetConsoleCtrlHandler(ConsoleCtrlHandler, FALSE);
    CloseHandle(g_StopEvent);
    g_StopEvent = nullptr;
    return 0;
}
