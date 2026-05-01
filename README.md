# VaultFS — C++ WinFsp Object-Store Prototype

This is the current C++ WinFsp prototype for the encrypted filesystem project.

It implements a Phase 2 prototype content-encryption layer. Logical directory entries are stored separately from physical object data, so mounted filenames no longer have to match the physical backing filenames:

```text
Mounted view: X:\file.txt
Maps:         D:\vault_backing\.maps\root.map
Object data:  D:\vault_backing\.objects\ab\cd\abcdef1234567890.data
```

## Requirements

1. Windows 10/11
2. Visual Studio 2022 with C++ workload
3. WinFsp installed, including the Developer files

Download WinFsp from:

```text
https://winfsp.dev/
```

Default expected WinFsp location:

```text
C:\Program Files (x86)\WinFsp
```

## Build

Open **Developer PowerShell for VS 2022** and run:

```powershell
msbuild VaultFs.sln /p:Configuration=Release /p:Platform=x64
```

Or open `VaultFs.sln` in Visual Studio and build `Release|x64`.

## Run

Create a backing directory:

```powershell
mkdir D:\vault_backing
```

Mount it as a drive:

```powershell
$env:VAULTFS_KEY = "change this development key"
.\x64\Release\VaultFs.exe D:\vault_backing X:
```

Now `X:` should show the contents of `D:\vault_backing`.

## Smoke test

With the filesystem mounted, run:

```powershell
.\scripts\smoke-test.ps1 -MountPoint X:
```

The script creates a temporary file on the mounted filesystem, verifies create/read/rename/delete behavior, and removes the test file before exiting.

Unmount:

```powershell
taskkill /im VaultFs.exe /f
```

or press Ctrl+C in the console.

## Current storage layout

- `.maps\<directory-id>.map` stores encrypted logical child-name metadata.
- `.objects\<id[0..1]>\<id[2..3]>\<id>.data` stores encrypted file contents.
- The root directory has the fixed ID `root`.

## Encryption

Set `VAULTFS_KEY` before mounting. The prototype derives a SHA-256 key from this value and uses a SHA-256 based random-access keystream per object ID and byte offset.

This protects file object contents in `.objects` and directory metadata contents in `.maps` from appearing as plaintext. Existing plaintext map files can still be read and are rewritten encrypted when modified. Physical map filenames, object IDs, file sizes, and directory shape are still visible, and file/map contents are not authenticated yet.

## Current operations

Implemented via WinFsp passthrough callbacks:

- Open/Create
- Read
- Write
- Flush
- GetFileInfo
- SetBasicInfo
- SetFileSize
- Rename
- Delete
- Create directory
- Read directory

## Next phase

The next phase should add metadata protection, authenticated encryption, and key management.
