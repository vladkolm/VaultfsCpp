#include "EncryptionUtilities.h"

#include "Utilities.h"

#include <bcrypt.h>

namespace
{
    NTSTATUS BCryptToNtStatus(NTSTATUS status)
    {
        return status;
    }

    void AppendUInt64Le(std::vector<BYTE>& out, UINT64 value)
    {
        for (int i = 0; i < 8; ++i)
            out.push_back(static_cast<BYTE>((value >> (i * 8)) & 0xff));
    }
}

bool g_MasterKeyReady = false;
std::array<BYTE, 32> g_MasterKey{};
const BYTE EncryptedMapMagic[8] = { 'V', 'F', 'S', 'M', 'A', 'P', '2', 0 };

NTSTATUS Sha256(const BYTE* data, ULONG dataSize, std::array<BYTE, 32>& digest)
{
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    DWORD objectLength = 0;
    DWORD resultLength = 0;

    NTSTATUS status = BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
    if (!NT_SUCCESS(status))
        return BCryptToNtStatus(status);

    status = BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&objectLength), sizeof(objectLength), &resultLength, 0);
    if (!NT_SUCCESS(status))
    {
        BCryptCloseAlgorithmProvider(algorithm, 0);
        return BCryptToNtStatus(status);
    }

    std::vector<BYTE> hashObject(objectLength);
    status = BCryptCreateHash(algorithm, &hash, hashObject.data(), objectLength, nullptr, 0, 0);
    if (NT_SUCCESS(status))
        status = BCryptHashData(hash, const_cast<PUCHAR>(data), dataSize, 0);
    if (NT_SUCCESS(status))
        status = BCryptFinishHash(hash, digest.data(), static_cast<ULONG>(digest.size()), 0);

    if (hash)
        BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(algorithm, 0);
    return BCryptToNtStatus(status);
}

NTSTATUS Sha256(const std::vector<BYTE>& data, std::array<BYTE, 32>& digest)
{
    return Sha256(data.data(), static_cast<ULONG>(data.size()), digest);
}

std::wstring HexFromBytes(const BYTE* data, size_t size)
{
    static constexpr wchar_t Hex[] = L"0123456789abcdef";
    std::wstring out;
    out.reserve(size * 2);
    for (size_t i = 0; i < size; ++i)
    {
        out.push_back(Hex[(data[i] >> 4) & 0x0f]);
        out.push_back(Hex[data[i] & 0x0f]);
    }
    return out;
}

NTSTATUS DeriveMasterKey(const std::wstring& passphrase, std::array<BYTE, 32>& key)
{
    std::string utf8 = WideToUtf8(passphrase);
    std::vector<BYTE> material;
    const char prefix[] = "VaultFS Phase2 key v1";
    material.insert(material.end(), prefix, prefix + sizeof(prefix) - 1);
    material.insert(material.end(), utf8.begin(), utf8.end());
    return Sha256(material, key);
}

NTSTATUS ApplyContentCipher(const std::array<BYTE, 32>& key, const std::wstring& id, UINT64 offset, BYTE* data, ULONG length)
{
    if (!g_MasterKeyReady)
        return STATUS_SUCCESS;
    if (length == 0)
        return STATUS_SUCCESS;

    std::string idUtf8 = WideToUtf8(id);
    ULONG done = 0;
    while (done < length)
    {
        UINT64 absolute = offset + done;
        UINT64 blockIndex = absolute / 32;
        ULONG blockOffset = static_cast<ULONG>(absolute % 32);

        std::vector<BYTE> material;
        const char prefix[] = "VaultFS Phase2 stream v1";
        material.insert(material.end(), prefix, prefix + sizeof(prefix) - 1);
        material.insert(material.end(), key.begin(), key.end());
        material.insert(material.end(), idUtf8.begin(), idUtf8.end());
        AppendUInt64Le(material, blockIndex);

        std::array<BYTE, 32> block{};
        NTSTATUS status = Sha256(material, block);
        if (!NT_SUCCESS(status))
            return status;

        ULONG take = std::min<ULONG>(length - done, static_cast<ULONG>(block.size()) - blockOffset);
        for (ULONG i = 0; i < take; ++i)
            data[done + i] ^= block[blockOffset + i];
        done += take;
    }

    return STATUS_SUCCESS;
}

std::wstring MapCipherId(const std::wstring& dirId)
{
    return L"map:" + dirId;
}

std::wstring DeriveStorageLabel(const std::wstring& purpose, const std::wstring& id)
{
    if (!g_MasterKeyReady)
        return id;

    std::string purposeUtf8 = WideToUtf8(purpose);
    std::string idUtf8 = WideToUtf8(id);
    std::vector<BYTE> material;
    const char prefix[] = "VaultFS metadata name v1";
    material.insert(material.end(), prefix, prefix + sizeof(prefix) - 1);
    material.insert(material.end(), g_MasterKey.begin(), g_MasterKey.end());
    material.insert(material.end(), purposeUtf8.begin(), purposeUtf8.end());
    material.push_back(0);
    material.insert(material.end(), idUtf8.begin(), idUtf8.end());

    std::array<BYTE, 32> digest{};
    if (!NT_SUCCESS(Sha256(material, digest)))
        return id;
    return HexFromBytes(digest.data(), digest.size());
}
