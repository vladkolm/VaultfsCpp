#include "FileOperation.h"

#include "EncryptionUtilities.h"
#include "Utilities.h"
#include "WindowsUtilities.h"

NTSTATUS FileOperation::GetVolumeInfo(FSP_FILE_SYSTEM*, FSP_FSCTL_VOLUME_INFO* VolumeInfo)
{
    memset(VolumeInfo, 0, sizeof(*VolumeInfo));
    VolumeInfo->TotalSize = 1024ull * 1024 * 1024 * 1024;
    VolumeInfo->FreeSize = 512ull * 1024 * 1024 * 1024;
    wcscpy_s(VolumeInfo->VolumeLabel, L"VaultFS2");
    return STATUS_SUCCESS;
}

NTSTATUS FileOperation::GetSecurityByName(FSP_FILE_SYSTEM*, PWSTR FileName, PUINT32 PFileAttributes, PSECURITY_DESCRIPTOR SecurityDescriptor, SIZE_T* PSecurityDescriptorSize)
{
    std::wstring logicalPath = FileName ? FileName : L"";
    std::lock_guard<std::recursive_mutex> lock(g_Vault->MapMutex);
    ResolvedPath resolved;
    NTSTATUS status = g_Vault->Resolver->ResolvePath(logicalPath, resolved);
    if (!NT_SUCCESS(status))
    {
        TraceEvent("GetSecurityByName", logicalPath, "status=0x" + Hex32(static_cast<UINT32>(status)));
        return status;
    }
    if (!resolved.Exists)
    {
        std::wstring parentId;
        std::wstring name;
        status = g_Vault->Resolver->ResolveParent(logicalPath, parentId, name);
        if (!NT_SUCCESS(status))
        {
            TraceEvent("GetSecurityByName", logicalPath, "status=0x" + Hex32(static_cast<UINT32>(status)) + " exists=0");
            return status;
        }
        TraceEvent("GetSecurityByName", logicalPath, "status=0xC0000034 exists=0");
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }
    if (PFileAttributes)
        *PFileAttributes = resolved.Type == ObjectType::Directory ? FILE_ATTRIBUTE_DIRECTORY : FILE_ATTRIBUTE_NORMAL;
    if (PSecurityDescriptorSize)
        *PSecurityDescriptorSize = 0;
    (void)SecurityDescriptor;
    std::ostringstream detail;
    detail << "status=0x00000000 exists=1 type=" << (resolved.Type == ObjectType::Directory ? "dir" : "file")
        << " size=" << resolved.Entry.FileSize;
    TraceEvent("GetSecurityByName", logicalPath, detail.str());
    return STATUS_SUCCESS;
}

NTSTATUS FileOperation::Create(FSP_FILE_SYSTEM*, PWSTR FileName, UINT32 CreateOptions, UINT32 GrantedAccess, UINT32 FileAttributes, PSECURITY_DESCRIPTOR, UINT64 AllocationSize, PVOID* PFileContext, FSP_FSCTL_FILE_INFO* FileInfo)
{
    std::wstring logicalPath = FileName ? FileName : L"";
    (void)GrantedAccess;

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
        ctx->Handle = CreateFileW(g_Vault->Store->ExistingDataPath(id).c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
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

NTSTATUS FileOperation::Open(FSP_FILE_SYSTEM*, PWSTR FileName, UINT32 CreateOptions, UINT32 GrantedAccess, PVOID* PFileContext, FSP_FSCTL_FILE_INFO* FileInfo)
{
    std::wstring logicalPath = FileName ? FileName : L"";
    (void)GrantedAccess;

    std::lock_guard<std::recursive_mutex> lock(g_Vault->MapMutex);
    ResolvedPath resolved;
    NTSTATUS status = g_Vault->Resolver->ResolvePath(logicalPath, resolved);
    if (!NT_SUCCESS(status))
    {
        std::ostringstream detail;
        detail << "status=0x" << Hex32(static_cast<UINT32>(status))
            << " createOptions=0x" << Hex32(CreateOptions);
        TraceEvent("Open", logicalPath, detail.str());
        return status;
    }
    if (!resolved.Exists)
    {
        std::ostringstream detail;
        detail << "status=0xC0000034 exists=0 createOptions=0x" << Hex32(CreateOptions);
        TraceEvent("Open", logicalPath, detail.str());
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }

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
        ctx->Handle = CreateFileW(g_Vault->Store->ExistingDataPath(resolved.Id).c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, flags, nullptr);
        if (ctx->Handle == INVALID_HANDLE_VALUE)
        {
            status = Win32ToNtStatus(GetLastError());
            std::ostringstream detail;
            detail << "status=0x" << Hex32(static_cast<UINT32>(status))
                << " backing-open-failed win32=" << GetLastError()
                << " logicalSize=" << ctx->LogicalSize
                << " createOptions=0x" << Hex32(CreateOptions);
            TraceEvent("Open", logicalPath, detail.str());
            return status;
        }
    }

    FileContext* rawCtx = ctx.release();
    g_Vault->LiveContexts.insert(rawCtx);
    *PFileContext = rawCtx;
    status = GetObjectInfo(resolved, FileInfo);
    std::ostringstream detail;
    detail << "status=0x" << Hex32(static_cast<UINT32>(status))
        << " type=" << (resolved.Type == ObjectType::Directory ? "dir" : "file")
        << " logicalSize=" << rawCtx->LogicalSize
        << " fileInfoSize=" << (FileInfo ? FileInfo->FileSize : 0)
        << " alloc=" << (FileInfo ? FileInfo->AllocationSize : 0)
        << " createOptions=0x" << Hex32(CreateOptions);
    TraceEvent("Open", logicalPath, detail.str());
    return status;
}

NTSTATUS FileOperation::Overwrite(FSP_FILE_SYSTEM*, PVOID FileContext0, UINT32 FileAttributes, BOOLEAN ReplaceFileAttributes, UINT64 AllocationSize, FSP_FSCTL_FILE_INFO* FileInfo)
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

void FileOperation::Cleanup(FSP_FILE_SYSTEM*, PVOID FileContext0, PWSTR FileName, ULONG Flags)
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

void FileOperation::Close(FSP_FILE_SYSTEM*, PVOID FileContext0)
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

NTSTATUS FileOperation::Read(FSP_FILE_SYSTEM*, PVOID FileContext0, PVOID Buffer, UINT64 Offset, ULONG Length, PULONG PBytesTransferred)
{
    auto ctx = static_cast<FileContext*>(FileContext0);
    if (!ctx || ctx->Type != ObjectType::File)
    {
        TraceEvent("Read", ctx ? ctx->LogicalPath : L"", "status=0xC0000008 invalid-context");
        return STATUS_INVALID_HANDLE;
    }
    if (ctx->Handle == INVALID_HANDLE_VALUE)
    {
        HANDLE reopened = CreateFileW(g_Vault->Store->ExistingDataPath(ctx->Id).c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (reopened == INVALID_HANDLE_VALUE)
        {
            NTSTATUS status = Win32ToNtStatus(GetLastError());
            *PBytesTransferred = 0;
            std::ostringstream detail;
            detail << "status=0x" << Hex32(static_cast<UINT32>(status))
                << " reopen-failed offset=" << Offset
                << " requested=" << Length
                << " returned=0 logicalSize=" << ctx->LogicalSize;
            TraceEvent("Read", ctx->LogicalPath, detail.str());
            return status;
        }

        LARGE_INTEGER li{};
        li.QuadPart = static_cast<LONGLONG>(Offset);
        ULONG requestedLength = Length;
        if (Offset >= ctx->LogicalSize)
        {
            CloseHandle(reopened);
            *PBytesTransferred = 0;
            std::ostringstream detail;
            detail << "status=0x00000000 reopened eof offset=" << Offset
                << " requested=" << requestedLength << " returned=0 logicalSize=" << ctx->LogicalSize;
            TraceEvent("Read", ctx->LogicalPath, detail.str());
            return STATUS_SUCCESS;
        }
        if (Offset + Length > ctx->LogicalSize)
            Length = static_cast<ULONG>(ctx->LogicalSize - Offset);
        if (!SetFilePointerEx(reopened, li, nullptr, FILE_BEGIN))
        {
            NTSTATUS status = Win32ToNtStatus(GetLastError());
            CloseHandle(reopened);
            *PBytesTransferred = 0;
            std::ostringstream detail;
            detail << "status=0x" << Hex32(static_cast<UINT32>(status))
                << " reopened set-pointer-failed offset=" << Offset
                << " requested=" << requestedLength
                << " clipped=" << Length
                << " logicalSize=" << ctx->LogicalSize;
            TraceEvent("Read", ctx->LogicalPath, detail.str());
            return status;
        }

        DWORD read = 0;
        if (!ReadFile(reopened, Buffer, Length, &read, nullptr))
        {
            NTSTATUS status = Win32ToNtStatus(GetLastError());
            CloseHandle(reopened);
            *PBytesTransferred = 0;
            std::ostringstream detail;
            detail << "status=0x" << Hex32(static_cast<UINT32>(status))
                << " reopened backing-read-failed offset=" << Offset
                << " requested=" << requestedLength
                << " clipped=" << Length
                << " returned=" << read
                << " logicalSize=" << ctx->LogicalSize;
            TraceEvent("Read", ctx->LogicalPath, detail.str());
            return status;
        }
        CloseHandle(reopened);

        NTSTATUS status = ApplyContentCipher(g_Vault->MasterKey, ctx->Id, Offset, static_cast<BYTE*>(Buffer), read);
        if (!NT_SUCCESS(status))
        {
            *PBytesTransferred = 0;
            std::ostringstream detail;
            detail << "status=0x" << Hex32(static_cast<UINT32>(status))
                << " reopened decrypt-failed offset=" << Offset
                << " requested=" << requestedLength
                << " clipped=" << Length
                << " returned=" << read
                << " logicalSize=" << ctx->LogicalSize;
            TraceEvent("Read", ctx->LogicalPath, detail.str());
            return status;
        }
        *PBytesTransferred = read;
        std::ostringstream detail;
        detail << "status=0x00000000 reopened offset=" << Offset
            << " requested=" << requestedLength
            << " clipped=" << Length
            << " returned=" << read
            << " logicalSize=" << ctx->LogicalSize;
        if (read > 0)
        {
            BYTE* bytes = static_cast<BYTE*>(Buffer);
            detail << " firstBytes=";
            ULONG sample = std::min<ULONG>(read, 16);
            static const char hex[] = "0123456789ABCDEF";
            for (ULONG i = 0; i < sample; ++i)
            {
                if (i)
                    detail << '-';
                detail << hex[(bytes[i] >> 4) & 0xf] << hex[bytes[i] & 0xf];
            }
        }
        TraceEvent("Read", ctx->LogicalPath, detail.str());
        return STATUS_SUCCESS;
    }
    if (Offset >= ctx->LogicalSize)
    {
        *PBytesTransferred = 0;
        std::ostringstream detail;
        detail << "status=0x00000000 eof offset=" << Offset
            << " requested=" << Length << " returned=0 logicalSize=" << ctx->LogicalSize;
        TraceEvent("Read", ctx->LogicalPath, detail.str());
        return STATUS_SUCCESS;
    }
    ULONG requestedLength = Length;
    if (Offset + Length > ctx->LogicalSize)
        Length = static_cast<ULONG>(ctx->LogicalSize - Offset);

    LARGE_INTEGER li{};
    li.QuadPart = static_cast<LONGLONG>(Offset);
    if (!SetFilePointerEx(ctx->Handle, li, nullptr, FILE_BEGIN))
    {
        NTSTATUS status = Win32ToNtStatus(GetLastError());
        std::ostringstream detail;
        detail << "status=0x" << Hex32(static_cast<UINT32>(status))
            << " set-pointer-failed offset=" << Offset
            << " requested=" << requestedLength
            << " clipped=" << Length
            << " logicalSize=" << ctx->LogicalSize;
        TraceEvent("Read", ctx->LogicalPath, detail.str());
        return status;
    }

    DWORD read = 0;
    if (!ReadFile(ctx->Handle, Buffer, Length, &read, nullptr))
    {
        NTSTATUS status = Win32ToNtStatus(GetLastError());
        std::ostringstream detail;
        detail << "status=0x" << Hex32(static_cast<UINT32>(status))
            << " backing-read-failed offset=" << Offset
            << " requested=" << requestedLength
            << " clipped=" << Length
            << " returned=" << read
            << " logicalSize=" << ctx->LogicalSize;
        TraceEvent("Read", ctx->LogicalPath, detail.str());
        return status;
    }
    NTSTATUS status = ApplyContentCipher(g_Vault->MasterKey, ctx->Id, Offset, static_cast<BYTE*>(Buffer), read);
    if (!NT_SUCCESS(status))
    {
        std::ostringstream detail;
        detail << "status=0x" << Hex32(static_cast<UINT32>(status))
            << " decrypt-failed offset=" << Offset
            << " requested=" << requestedLength
            << " clipped=" << Length
            << " returned=" << read
            << " logicalSize=" << ctx->LogicalSize;
        TraceEvent("Read", ctx->LogicalPath, detail.str());
        return status;
    }
    *PBytesTransferred = read;
    std::ostringstream detail;
    detail << "status=0x00000000 offset=" << Offset
        << " requested=" << requestedLength
        << " clipped=" << Length
        << " returned=" << read
        << " logicalSize=" << ctx->LogicalSize;
    if (read > 0)
    {
        BYTE* bytes = static_cast<BYTE*>(Buffer);
        detail << " firstBytes=";
        ULONG sample = std::min<ULONG>(read, 16);
        static const char hex[] = "0123456789ABCDEF";
        for (ULONG i = 0; i < sample; ++i)
        {
            if (i)
                detail << '-';
            detail << hex[(bytes[i] >> 4) & 0xf] << hex[bytes[i] & 0xf];
        }
    }
    TraceEvent("Read", ctx->LogicalPath, detail.str());
    return STATUS_SUCCESS;
}

NTSTATUS FileOperation::Write(FSP_FILE_SYSTEM*, PVOID FileContext0, PVOID Buffer, UINT64 Offset, ULONG Length, BOOLEAN WriteToEndOfFile, BOOLEAN ConstrainedIo, PULONG PBytesTransferred, FSP_FSCTL_FILE_INFO* FileInfo)
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


NTSTATUS FileOperation::Flush(FSP_FILE_SYSTEM*, PVOID FileContext0, FSP_FSCTL_FILE_INFO* FileInfo)
{
    auto ctx = static_cast<FileContext*>(FileContext0);
    if (ctx && ctx->Handle == INVALID_HANDLE_VALUE)
        return FileOperation::GetFileInfo(nullptr, FileContext0, FileInfo);
    if (ctx && ctx->Type == ObjectType::File && ctx->Handle != INVALID_HANDLE_VALUE)
    {
        if (!FlushFileBuffers(ctx->Handle))
            return Win32ToNtStatus(GetLastError());
        return GetFileInfoByHandle(ctx->Handle, ctx->Id, ctx->Type, FileInfo, ctx->LogicalSize);
    }
    return STATUS_SUCCESS;
}

NTSTATUS FileOperation::GetFileInfo(FSP_FILE_SYSTEM*, PVOID FileContext0, FSP_FSCTL_FILE_INFO* FileInfo)
{
    auto ctx = static_cast<FileContext*>(FileContext0);
    if (!ctx)
    {
        TraceEvent("GetFileInfo", L"", "status=0xC0000008 invalid-context");
        return STATUS_INVALID_HANDLE;
    }

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
        std::ostringstream detail;
        detail << "status=0x00000000 deleted=1 type=" << (ctx->Type == ObjectType::Directory ? "dir" : "file")
            << " ctxLogicalSize=" << ctx->LogicalSize
            << " fileInfoSize=" << FileInfo->FileSize
            << " alloc=" << FileInfo->AllocationSize;
        TraceEvent("GetFileInfo", ctx->LogicalPath, detail.str());
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
    std::ostringstream detail;
    detail << "status=0x" << Hex32(static_cast<UINT32>(status))
        << " type=" << (ctx->Type == ObjectType::Directory ? "dir" : "file")
        << " ctxLogicalSize=" << ctx->LogicalSize
        << " fileInfoSize=" << (FileInfo ? FileInfo->FileSize : 0)
        << " alloc=" << (FileInfo ? FileInfo->AllocationSize : 0);
    TraceEvent("GetFileInfo", ctx->LogicalPath, detail.str());
    return status;
}

NTSTATUS FileOperation::SetBasicInfo(FSP_FILE_SYSTEM*, PVOID FileContext0, UINT32 FileAttributes, UINT64 CreationTime, UINT64 LastAccessTime, UINT64 LastWriteTime, UINT64 ChangeTime, FSP_FSCTL_FILE_INFO* FileInfo)
{
    auto ctx = static_cast<FileContext*>(FileContext0);
    if (!ctx)
        return STATUS_INVALID_HANDLE;
    if (ctx->LogicalDeleted)
        return FileOperation::GetFileInfo(nullptr, FileContext0, FileInfo);

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
        return FileOperation::GetFileInfo(nullptr, FileContext0, FileInfo);
    return GetFileInfoByHandle(ctx->Handle, ctx->Id, ctx->Type, FileInfo, ctx->LogicalSize);
}

NTSTATUS FileOperation::SetFileSize(FSP_FILE_SYSTEM*, PVOID FileContext0, UINT64 NewSize, BOOLEAN SetAllocationSize, FSP_FSCTL_FILE_INFO* FileInfo)
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

NTSTATUS FileOperation::CanDelete(FSP_FILE_SYSTEM*, PVOID FileContext0, PWSTR FileName)
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

NTSTATUS FileOperation::Rename(FSP_FILE_SYSTEM*, PVOID FileContext0, PWSTR FileName, PWSTR NewFileName, BOOLEAN ReplaceIfExists)
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

NTSTATUS FileOperation::ReadDirectory(FSP_FILE_SYSTEM*, PVOID FileContext0, PWSTR Pattern, PWSTR Marker, PVOID Buffer, ULONG Length, PULONG PBytesTransferred)
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

NTSTATUS FileOperation::GetDirInfoByName(FSP_FILE_SYSTEM*, PVOID FileContext0, PWSTR FileName, FSP_FSCTL_DIR_INFO* DirInfo)
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

NTSTATUS FileOperation::SetDelete(FSP_FILE_SYSTEM*, PVOID FileContext0, PWSTR FileName, BOOLEAN DeleteFile)
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


void FileOperation::Register(FSP_FILE_SYSTEM_INTERFACE& iface)
{
    iface.GetVolumeInfo = FileOperation::GetVolumeInfo;
    iface.GetSecurityByName = FileOperation::GetSecurityByName;
    iface.Create = FileOperation::Create;
    iface.Open = FileOperation::Open;
    iface.Overwrite = FileOperation::Overwrite;
    iface.Cleanup = FileOperation::Cleanup;
    iface.Close = FileOperation::Close;
    iface.Read = FileOperation::Read;
    iface.Write = FileOperation::Write;
    iface.Flush = FileOperation::Flush;
    iface.GetFileInfo = FileOperation::GetFileInfo;
    iface.SetBasicInfo = FileOperation::SetBasicInfo;
    iface.SetFileSize = FileOperation::SetFileSize;
    iface.CanDelete = FileOperation::CanDelete;
    iface.SetDelete = FileOperation::SetDelete;
    iface.Rename = FileOperation::Rename;
    iface.ReadDirectory = FileOperation::ReadDirectory;
    iface.GetDirInfoByName = FileOperation::GetDirInfoByName;
}
