#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
typedef long NTSTATUS, *PNTSTATUS;
#include <winfsp/winfsp.h>

#include <array>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <vector>

class ObjectStore;
class PathResolver;

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
    std::wstring TracePath;
    std::unique_ptr<ObjectStore> Store;
    std::unique_ptr<PathResolver> Resolver;
    std::array<BYTE, 32> MasterKey{};
    std::recursive_mutex MapMutex;
    std::mutex TraceMutex;
    std::set<FileContext*> LiveContexts;
    std::vector<std::unique_ptr<FileContext>> RetiredContexts;
    FSP_FILE_SYSTEM* FileSystem = nullptr;
};
