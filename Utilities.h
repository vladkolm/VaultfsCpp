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
#include <vector>

#include "Data.h"

UINT32 NormalizeFileAttributes(UINT32 attributes, ObjectType type);
NTSTATUS Win32ToNtStatus(DWORD error);
std::wstring TrimTrailingSlash(std::wstring path);
std::string WideToUtf8(const std::wstring& value);
std::vector<std::wstring> SplitLogicalPath(const std::wstring& path);
std::wstring ParentLogicalPath(const std::wstring& path);
bool IsName(const wchar_t* value, const wchar_t* expected);
bool CaseInsensitiveEquals(const wchar_t* left, const wchar_t* right);
int CaseInsensitiveCompare(const wchar_t* left, const wchar_t* right);
bool CaseInsensitiveCharEquals(wchar_t left, wchar_t right);
bool WildcardMatch(const wchar_t* pattern, const wchar_t* text);
void CopyDirInfoName(FSP_FSCTL_DIR_INFO* dirInfo, const std::wstring& name);
size_t DirInfoSizeForName(const std::wstring& name);
UINT64 FileTimeToUInt64(const FILETIME& ft);
UINT64 CurrentFileTimeUInt64();
UINT64 RoundUp(UINT64 value, UINT64 quantum);
std::string Hex32(UINT32 value);
