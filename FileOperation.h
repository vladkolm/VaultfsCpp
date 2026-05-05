#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
typedef long NTSTATUS, *PNTSTATUS;
#include <winfsp/winfsp.h>

class FileOperation
{
public:
    static void Register(FSP_FILE_SYSTEM_INTERFACE& iface);

    static NTSTATUS GetVolumeInfo(FSP_FILE_SYSTEM*, FSP_FSCTL_VOLUME_INFO* VolumeInfo);
    static NTSTATUS GetSecurityByName(FSP_FILE_SYSTEM*, PWSTR FileName, PUINT32 PFileAttributes, PSECURITY_DESCRIPTOR SecurityDescriptor, SIZE_T* PSecurityDescriptorSize);
    static NTSTATUS Create(FSP_FILE_SYSTEM*, PWSTR FileName, UINT32 CreateOptions, UINT32 GrantedAccess, UINT32 FileAttributes, PSECURITY_DESCRIPTOR, UINT64 AllocationSize, PVOID* PFileContext, FSP_FSCTL_FILE_INFO* FileInfo);
    static NTSTATUS Open(FSP_FILE_SYSTEM*, PWSTR FileName, UINT32 CreateOptions, UINT32 GrantedAccess, PVOID* PFileContext, FSP_FSCTL_FILE_INFO* FileInfo);
    static NTSTATUS Overwrite(FSP_FILE_SYSTEM*, PVOID FileContext0, UINT32 FileAttributes, BOOLEAN ReplaceFileAttributes, UINT64 AllocationSize, FSP_FSCTL_FILE_INFO* FileInfo);
    static void Cleanup(FSP_FILE_SYSTEM*, PVOID FileContext0, PWSTR FileName, ULONG Flags);
    static void Close(FSP_FILE_SYSTEM*, PVOID FileContext0);
    static NTSTATUS Read(FSP_FILE_SYSTEM*, PVOID FileContext0, PVOID Buffer, UINT64 Offset, ULONG Length, PULONG PBytesTransferred);
    static NTSTATUS Write(FSP_FILE_SYSTEM*, PVOID FileContext0, PVOID Buffer, UINT64 Offset, ULONG Length, BOOLEAN WriteToEndOfFile, BOOLEAN ConstrainedIo, PULONG PBytesTransferred, FSP_FSCTL_FILE_INFO* FileInfo);
    static NTSTATUS Flush(FSP_FILE_SYSTEM*, PVOID FileContext0, FSP_FSCTL_FILE_INFO* FileInfo);
    static NTSTATUS GetFileInfo(FSP_FILE_SYSTEM*, PVOID FileContext0, FSP_FSCTL_FILE_INFO* FileInfo);
    static NTSTATUS SetBasicInfo(FSP_FILE_SYSTEM*, PVOID FileContext0, UINT32 FileAttributes, UINT64 CreationTime, UINT64 LastAccessTime, UINT64 LastWriteTime, UINT64 ChangeTime, FSP_FSCTL_FILE_INFO* FileInfo);
    static NTSTATUS SetFileSize(FSP_FILE_SYSTEM*, PVOID FileContext0, UINT64 NewSize, BOOLEAN SetAllocationSize, FSP_FSCTL_FILE_INFO* FileInfo);
    static NTSTATUS CanDelete(FSP_FILE_SYSTEM*, PVOID FileContext0, PWSTR FileName);
    static NTSTATUS SetDelete(FSP_FILE_SYSTEM*, PVOID FileContext0, PWSTR FileName, BOOLEAN DeleteFile);
    static NTSTATUS Rename(FSP_FILE_SYSTEM*, PVOID FileContext0, PWSTR FileName, PWSTR NewFileName, BOOLEAN ReplaceIfExists);
    static NTSTATUS ReadDirectory(FSP_FILE_SYSTEM*, PVOID FileContext0, PWSTR Pattern, PWSTR Marker, PVOID Buffer, ULONG Length, PULONG PBytesTransferred);
    static NTSTATUS GetDirInfoByName(FSP_FILE_SYSTEM*, PVOID FileContext0, PWSTR FileName, FSP_FSCTL_DIR_INFO* DirInfo);
};
