#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
typedef long NTSTATUS, *PNTSTATUS;
#include <windows.h>

#include <map>
#include <string>
#include <vector>

#include "Data.h"
#include "ObjectStore.h"

class DirectoryMap
{
public:
    std::map<std::wstring, MapEntry> Entries;

    std::map<std::wstring, MapEntry>::iterator Find(const std::wstring& name);
    std::map<std::wstring, MapEntry>::const_iterator Find(const std::wstring& name) const;

    static NTSTATUS Load(const ObjectStore& store, const std::wstring& dirId, DirectoryMap& map);
    static NTSTATUS Save(const ObjectStore& store, const std::wstring& dirId, const DirectoryMap& map);

private:
    static NTSTATUS WriteAtomicFile(const std::wstring& path, const std::vector<BYTE>& bytes);
    static NTSTATUS WriteFileFullyAndFlush(const std::wstring& path, const std::vector<BYTE>& bytes);
    static std::wstring MakeTempPath(const std::wstring& path);
    static NTSTATUS DecodeMapText(const std::wstring& dirId, const std::string& raw, std::string& text);
    static std::string ReadJsonString(const std::string& text, size_t quote);
    static UINT64 ReadJsonUInt64(const std::string& text, const char* key, UINT64 fallback);
};
