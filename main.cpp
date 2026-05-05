#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
typedef long NTSTATUS, *PNTSTATUS;
#include <winfsp/winfsp.h>
#include "Data.h"
#include "EncryptionUtilities.h"
#include "JsonUtils.h"
#include "Utilities.h"
#include "ObjectStore.h"
#include "DirectoryMap.h"
#include "PathResolver.h"
#include "WindowsUtilities.h"
#include "FileOperation.h"

#include <array>
#include <algorithm>
#include <cstdlib>
#include <cstdio>
#include <cwchar>
#include <cstring>
#include <fstream>
#include <map>
#include <memory>
#include <mutex>
#include <random>
#include <set>
#include <sstream>
#include <string>
#include <vector>

static wchar_t DiskDeviceName[] = L"WinFsp.Disk";

const wchar_t RootId[] = L"root";
const UINT64 PhysicalSizeQuantum = 4096;
VaultContext* g_Vault = nullptr;
HANDLE g_StopEvent = nullptr;

int wmain(int argc, wchar_t** argv)
{
    bool noEncryption = false;
    std::vector<std::wstring> positional;
    for (int i = 1; i < argc; ++i)
    {
        if (CaseInsensitiveEquals(argv[i], L"--NoEncryption"))
        {
            noEncryption = true;
        }
        else if (argv[i] && argv[i][0] == L'-')
        {
            fwprintf(stderr, L"Unknown option: %s\n", argv[i]);
            fwprintf(stderr, L"Usage: %s [--NoEncryption] <backing-directory> <mount-point>\n", argv[0]);
            fwprintf(stderr, L"Example: %s D:\\vault_backing X:\n", argv[0]);
            fwprintf(stderr, L"Example: %s --NoEncryption D:\\vault_backing X:\n", argv[0]);
            return 2;
        }
        else
        {
            positional.push_back(argv[i] ? argv[i] : L"");
        }
    }

    if (positional.size() != 2)
    {
        fwprintf(stderr, L"Usage: %s [--NoEncryption] <backing-directory> <mount-point>\n", argv[0]);
        fwprintf(stderr, L"Example: %s D:\\vault_backing X:\n", argv[0]);
        fwprintf(stderr, L"Example: %s --NoEncryption D:\\vault_backing X:\n", argv[0]);
        return 2;
    }

    VaultContext vault{};
    vault.BackingRoot = TrimTrailingSlash(positional[0]);
    if (noEncryption)
    {
        g_MasterKey = {};
        g_MasterKeyReady = false;
    }
    else
    {
        wchar_t* keyEnv = nullptr;
        size_t keyEnvLength = 0;
        errno_t keyEnvError = _wdupenv_s(&keyEnv, &keyEnvLength, L"VAULTFS_KEY");
        if (keyEnvError != 0 || !keyEnv || keyEnv[0] == L'\0')
        {
            if (keyEnv)
                free(keyEnv);
            fwprintf(stderr, L"VAULTFS_KEY must be set unless --NoEncryption is used.\n");
            return 2;
        }
        NTSTATUS keyStatus = DeriveMasterKey(keyEnv, vault.MasterKey);
        free(keyEnv);
        if (!NT_SUCCESS(keyStatus))
        {
            fwprintf(stderr, L"Failed to derive encryption key: 0x%08X\n", keyStatus);
            return 1;
        }
        g_MasterKey = vault.MasterKey;
        g_MasterKeyReady = true;
    }

    wchar_t* traceEnv = nullptr;
    size_t traceEnvLength = 0;
    if (0 == _wdupenv_s(&traceEnv, &traceEnvLength, L"VAULTFS_TRACE") && traceEnv && traceEnv[0] != L'\0')
        vault.TracePath = traceEnv;
    if (traceEnv)
        free(traceEnv);

    vault.Store = std::make_unique<ObjectStore>(vault.BackingRoot);
    vault.Store->Initialize();
    vault.Resolver = std::make_unique<PathResolver>(*vault.Store);
    g_Vault = &vault;

    g_StopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!g_StopEvent)
    {
        fwprintf(stderr, L"CreateEvent failed: %lu\n", GetLastError());
        return 1;
    }
    if (!SetConsoleCtrlHandler(ConsoleCtrlHandler, TRUE))
    {
        fwprintf(stderr, L"SetConsoleCtrlHandler failed: %lu\n", GetLastError());
        CloseHandle(g_StopEvent);
        g_StopEvent = nullptr;
        return 1;
    }

    DirectoryMap root;
    DirectoryMap::Load(*vault.Store, RootId, root);

    FSP_FSCTL_VOLUME_PARAMS params{};
    params.Version = sizeof(params);
    params.SectorSize = 4096;
    params.SectorsPerAllocationUnit = 1;
    params.VolumeSerialNumber = 0x19831116;
    params.FileInfoTimeout = 0;
    params.DirInfoTimeoutValid = 1;
    params.DirInfoTimeout = 0;
    params.CaseSensitiveSearch = 0;
    params.CasePreservedNames = 1;
    params.UnicodeOnDisk = 1;
    params.PersistentAcls = 0;
    params.PostCleanupWhenModifiedOnly = 1;
    params.PassQueryDirectoryFileName = 1;
    params.FlushAndPurgeOnCleanup = 1;
    wcscpy_s(params.FileSystemName, L"VaultFS2");

    FSP_FILE_SYSTEM_INTERFACE iface{};
    FileOperation::Register(iface);

    NTSTATUS status = FspFileSystemCreate(DiskDeviceName, &params, &iface, &vault.FileSystem);
    if (!NT_SUCCESS(status))
    {
        fwprintf(stderr, L"FspFileSystemCreate failed: 0x%08X\n", status);
        SetConsoleCtrlHandler(ConsoleCtrlHandler, FALSE);
        CloseHandle(g_StopEvent);
        g_StopEvent = nullptr;
        return 1;
    }

    vault.FileSystem->UserContext = &vault;
    status = FspFileSystemSetMountPoint(vault.FileSystem, const_cast<PWSTR>(positional[1].c_str()));
    if (!NT_SUCCESS(status))
    {
        fwprintf(stderr, L"FspFileSystemSetMountPoint failed: 0x%08X\n", status);
        FspFileSystemDelete(vault.FileSystem);
        SetConsoleCtrlHandler(ConsoleCtrlHandler, FALSE);
        CloseHandle(g_StopEvent);
        g_StopEvent = nullptr;
        return 1;
    }

    status = FspFileSystemStartDispatcher(vault.FileSystem, 0);
    if (!NT_SUCCESS(status))
    {
        fwprintf(stderr, L"FspFileSystemStartDispatcher failed: 0x%08X\n", status);
        FspFileSystemDelete(vault.FileSystem);
        SetConsoleCtrlHandler(ConsoleCtrlHandler, FALSE);
        CloseHandle(g_StopEvent);
        g_StopEvent = nullptr;
        return 1;
    }

    wprintf(L"Mounted %s at %s using short object IDs (%s). Press Ctrl-C to stop.\n",
        vault.BackingRoot.c_str(),
        positional[1].c_str(),
        noEncryption ? L"no encryption" : L"encrypted");
    WaitForSingleObject(g_StopEvent, INFINITE);

    FspFileSystemStopDispatcher(vault.FileSystem);
    FspFileSystemDelete(vault.FileSystem);
    SetConsoleCtrlHandler(ConsoleCtrlHandler, FALSE);
    CloseHandle(g_StopEvent);
    g_StopEvent = nullptr;
    return 0;
}
