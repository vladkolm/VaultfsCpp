#include "ObjectStore.h"

#include "Utilities.h"

#include <random>
#include <utility>

ObjectStore::ObjectStore(std::wstring root) : root_(std::move(root))
{
}

void ObjectStore::Initialize()
{
    EnsureDirectory(root_);
    EnsureDirectory(ObjectsRoot());
    EnsureDirectory(MapsRoot());
}

std::wstring ObjectStore::GenerateId() const
{
    std::random_device rd;
    std::mt19937_64 gen((static_cast<UINT64>(rd()) << 32) ^ rd());
    std::uniform_int_distribution<UINT64> dist;
    UINT64 hi = dist(gen);
    UINT64 lo = dist(gen);

    wchar_t buf[33]{};
    swprintf_s(buf, L"%016llx%016llx", static_cast<unsigned long long>(hi), static_cast<unsigned long long>(lo));
    return buf;
}

std::wstring ObjectStore::DataPath(const std::wstring& id) const
{
    std::wstring label = ObjectLabel(id);
    std::wstring path = ObjectsRoot() + L"\\" + label.substr(0, 2);
    path += L"\\";
    path += label.substr(2, 2);
    path += L"\\";
    path += label;
    path += L".data";
    return path;
}

std::wstring ObjectStore::LegacyDataPath(const std::wstring& id) const
{
    std::wstring path = ObjectsRoot() + L"\\" + id.substr(0, 2);
    path += L"\\";
    path += id.substr(2, 2);
    path += L"\\";
    path += id;
    path += L".data";
    return path;
}

std::wstring ObjectStore::ExistingDataPath(const std::wstring& id) const
{
    std::wstring path = DataPath(id);
    if (GetFileAttributesW(path.c_str()) != INVALID_FILE_ATTRIBUTES)
        return path;
    std::wstring legacy = LegacyDataPath(id);
    if (GetFileAttributesW(legacy.c_str()) != INVALID_FILE_ATTRIBUTES)
        return legacy;
    return path;
}

std::wstring ObjectStore::MapPath(const std::wstring& dirId) const
{
    return MapsRoot() + L"\\" + MapLabel(dirId) + L".map";
}

std::wstring ObjectStore::LegacyMapPath(const std::wstring& dirId) const
{
    return MapsRoot() + L"\\" + dirId + L".map";
}

std::wstring ObjectStore::ExistingMapPath(const std::wstring& dirId) const
{
    std::wstring path = MapPath(dirId);
    if (GetFileAttributesW(path.c_str()) != INVALID_FILE_ATTRIBUTES)
        return path;
    std::wstring legacy = LegacyMapPath(dirId);
    if (GetFileAttributesW(legacy.c_str()) != INVALID_FILE_ATTRIBUTES)
        return legacy;
    return path;
}

NTSTATUS ObjectStore::CreateFileObject(const std::wstring& id, UINT64 allocationSize)
{
    NTSTATUS status = EnsureObjectShard(id);
    if (!NT_SUCCESS(status))
        return status;
    std::wstring path = DataPath(id);
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE)
        return Win32ToNtStatus(GetLastError());
    (void)allocationSize;
    CloseHandle(h);
    return STATUS_SUCCESS;
}

NTSTATUS ObjectStore::DeleteObject(const std::wstring& id, ObjectType type)
{
    if (type == ObjectType::File)
    {
        if (!DeleteFileW(ExistingDataPath(id).c_str()))
            return Win32ToNtStatus(GetLastError());
    }
    else if (id != RootId)
    {
        if (!DeleteFileW(ExistingMapPath(id).c_str()))
            return Win32ToNtStatus(GetLastError());
    }
    return STATUS_SUCCESS;
}

std::wstring ObjectStore::ObjectsRoot() const
{
    return root_ + L"\\.objects";
}

std::wstring ObjectStore::MapsRoot() const
{
    return root_ + L"\\.maps";
}

std::wstring ObjectStore::ObjectLabel(const std::wstring& id)
{
    return DeriveStorageLabel(L"object", id);
}

std::wstring ObjectStore::MapLabel(const std::wstring& id)
{
    return DeriveStorageLabel(L"map", id);
}

NTSTATUS ObjectStore::EnsureObjectShard(const std::wstring& id) const
{
    std::wstring label = ObjectLabel(id);
    std::wstring a = ObjectsRoot() + L"\\" + label.substr(0, 2);
    std::wstring b = a + L"\\" + label.substr(2, 2);
    NTSTATUS status = EnsureDirectory(a);
    if (!NT_SUCCESS(status))
        return status;
    return EnsureDirectory(b);
}

NTSTATUS ObjectStore::EnsureDirectory(const std::wstring& path)
{
    if (CreateDirectoryW(path.c_str(), nullptr))
        return STATUS_SUCCESS;
    DWORD error = GetLastError();
    if (error == ERROR_ALREADY_EXISTS)
        return STATUS_SUCCESS;
    return Win32ToNtStatus(error);
}
