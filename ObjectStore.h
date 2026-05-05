#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
typedef long NTSTATUS, *PNTSTATUS;
#include <windows.h>

#include <string>

#include "Data.h"

class ObjectStore
{
public:
    explicit ObjectStore(std::wstring root);

    void Initialize();
    std::wstring GenerateId() const;
    std::wstring DataPath(const std::wstring& id) const;
    std::wstring LegacyDataPath(const std::wstring& id) const;
    std::wstring ExistingDataPath(const std::wstring& id) const;
    std::wstring MapPath(const std::wstring& dirId) const;
    std::wstring LegacyMapPath(const std::wstring& dirId) const;
    std::wstring ExistingMapPath(const std::wstring& dirId) const;
    NTSTATUS CreateFileObject(const std::wstring& id, UINT64 allocationSize);
    NTSTATUS DeleteObject(const std::wstring& id, ObjectType type);

private:
    std::wstring ObjectsRoot() const;
    std::wstring MapsRoot() const;
    static std::wstring ObjectLabel(const std::wstring& id);
    static std::wstring MapLabel(const std::wstring& id);
    NTSTATUS EnsureObjectShard(const std::wstring& id) const;
    static NTSTATUS EnsureDirectory(const std::wstring& path);

    std::wstring root_;
};
