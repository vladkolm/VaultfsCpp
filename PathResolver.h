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
#include "ObjectStore.h"

class PathResolver
{
public:
    explicit PathResolver(const ObjectStore& store);

    NTSTATUS ResolvePath(const std::wstring& path, ResolvedPath& resolved) const;
    NTSTATUS ResolveParent(const std::wstring& path, std::wstring& parentId, std::wstring& name) const;

private:
    const ObjectStore& store_;
};
