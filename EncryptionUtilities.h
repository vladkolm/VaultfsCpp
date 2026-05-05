#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
typedef long NTSTATUS, *PNTSTATUS;
#include <windows.h>

#include <array>
#include <string>
#include <vector>

extern bool g_MasterKeyReady;
extern std::array<BYTE, 32> g_MasterKey;
extern const BYTE EncryptedMapMagic[8];

NTSTATUS Sha256(const BYTE* data, ULONG dataSize, std::array<BYTE, 32>& digest);
NTSTATUS Sha256(const std::vector<BYTE>& data, std::array<BYTE, 32>& digest);
std::wstring HexFromBytes(const BYTE* data, size_t size);
NTSTATUS DeriveMasterKey(const std::wstring& passphrase, std::array<BYTE, 32>& key);
NTSTATUS ApplyContentCipher(const std::array<BYTE, 32>& key, const std::wstring& id, UINT64 offset, BYTE* data, ULONG length);
std::wstring MapCipherId(const std::wstring& dirId);
std::wstring DeriveStorageLabel(const std::wstring& purpose, const std::wstring& id);
