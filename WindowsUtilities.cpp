#include "WindowsUtilities.h"

#include "DirectoryMap.h"
#include "EncryptionUtilities.h"
#include "ObjectStore.h"
#include "Utilities.h"

#include <algorithm>
#include <cstring>
#include <fstream>
#include <functional>
#include <mutex>
#include <sstream>
#include <vector>

std::wstring CurrentProcessImageName(UINT32 pid)
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

void TraceEvent(const char* operation, const std::wstring& path, const std::string& detail)
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

BOOL WINAPI ConsoleCtrlHandler(DWORD ctrlType)
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

void FillFileInfoFromAttributes(const WIN32_FILE_ATTRIBUTE_DATA& data, const std::wstring& id, ObjectType type, FSP_FSCTL_FILE_INFO* info)
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

NTSTATUS GetObjectInfo(const ResolvedPath& resolved, FSP_FSCTL_FILE_INFO* info)
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

NTSTATUS GetFileInfoByHandle(HANDLE h, const std::wstring& id, ObjectType type, FSP_FSCTL_FILE_INFO* info, UINT64 logicalSize)
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

NTSTATUS WriteEncryptedZeros(FileContext* ctx, UINT64 offset, UINT64 length)
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

NTSTATUS SetEncryptedFileSize(FileContext* ctx, UINT64 newSize)
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

NTSTATUS SetPhysicalPaddedFileSize(FileContext* ctx, UINT64 logicalSize)
{
    LARGE_INTEGER li{};
    li.QuadPart = static_cast<LONGLONG>(RoundUp(logicalSize, PhysicalSizeQuantum));
    if (!SetFilePointerEx(ctx->Handle, li, nullptr, FILE_BEGIN) || !SetEndOfFile(ctx->Handle))
        return Win32ToNtStatus(GetLastError());
    return STATUS_SUCCESS;
}

NTSTATUS UpdateEncryptedMapMetadata(FileContext* ctx, UINT64 logicalSize)
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
