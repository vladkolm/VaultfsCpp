#include "PathResolver.h"

#include "DirectoryMap.h"

PathResolver::PathResolver(const ObjectStore& store) : store_(store)
{
}

NTSTATUS PathResolver::ResolvePath(const std::wstring& path, ResolvedPath& resolved) const
{
    auto parts = SplitLogicalPath(path);
    resolved = {};
    resolved.Id = RootId;
    resolved.Type = ObjectType::Directory;
    resolved.Exists = true;
    resolved.Entry.Id = RootId;
    resolved.Entry.Type = ObjectType::Directory;
    resolved.Entry.FileAttributes = FILE_ATTRIBUTE_DIRECTORY;

    if (parts.empty())
        return STATUS_SUCCESS;

    std::wstring current = RootId;
    for (size_t i = 0; i < parts.size(); ++i)
    {
        DirectoryMap map;
        NTSTATUS status = DirectoryMap::Load(store_, current, map);
        if (!NT_SUCCESS(status))
            return status;

        auto it = map.Find(parts[i]);
        if (it == map.Entries.end())
        {
            resolved.Exists = false;
            resolved.ParentId = current;
            resolved.Name = parts[i];
            return i + 1 == parts.size() ? STATUS_SUCCESS : STATUS_OBJECT_NAME_NOT_FOUND;
        }

        resolved.Exists = true;
        resolved.Id = it->second.Id;
        resolved.Type = it->second.Type;
        resolved.ParentId = current;
        resolved.Name = it->first;
        resolved.Entry = it->second;
        current = it->second.Id;

        if (i + 1 < parts.size() && it->second.Type != ObjectType::Directory)
            return STATUS_NOT_A_DIRECTORY;
    }
    return STATUS_SUCCESS;
}

NTSTATUS PathResolver::ResolveParent(const std::wstring& path, std::wstring& parentId, std::wstring& name) const
{
    auto parts = SplitLogicalPath(path);
    if (parts.empty())
        return STATUS_ACCESS_DENIED;

    name = parts.back();
    parts.pop_back();
    std::wstring parentPath;
    for (const auto& part : parts)
    {
        parentPath += L"\\";
        parentPath += part;
    }

    ResolvedPath parent;
    NTSTATUS status = ResolvePath(parentPath, parent);
    if (!NT_SUCCESS(status))
        return status;
    if (!parent.Exists)
        return STATUS_OBJECT_PATH_NOT_FOUND;
    if (parent.Type != ObjectType::Directory)
        return STATUS_NOT_A_DIRECTORY;
    parentId = parent.Id;
    return STATUS_SUCCESS;
}
