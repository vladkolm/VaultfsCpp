#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
typedef long NTSTATUS, *PNTSTATUS;
#include <winfsp/winfsp.h>

#include <string>

#include "Data.h"

std::wstring CurrentProcessImageName(UINT32 pid);
void TraceEvent(const char* operation, const std::wstring& path, const std::string& detail);
BOOL WINAPI ConsoleCtrlHandler(DWORD ctrlType);
void FillFileInfoFromAttributes(const WIN32_FILE_ATTRIBUTE_DATA& data, const std::wstring& id, ObjectType type, FSP_FSCTL_FILE_INFO* info);
NTSTATUS GetObjectInfo(const ResolvedPath& resolved, FSP_FSCTL_FILE_INFO* info);
NTSTATUS GetFileInfoByHandle(HANDLE h, const std::wstring& id, ObjectType type, FSP_FSCTL_FILE_INFO* info, UINT64 logicalSize = UINT64_MAX);
NTSTATUS WriteEncryptedZeros(FileContext* ctx, UINT64 offset, UINT64 length);
NTSTATUS SetEncryptedFileSize(FileContext* ctx, UINT64 newSize);
NTSTATUS SetPhysicalPaddedFileSize(FileContext* ctx, UINT64 logicalSize);
NTSTATUS UpdateEncryptedMapMetadata(FileContext* ctx, UINT64 logicalSize);
