#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <string>

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
