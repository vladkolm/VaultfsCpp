param(
    [Parameter(Mandatory = $true)]
    [string]$MountPoint,

    [string]$BackingRoot = "",

    [int]$Iterations = 32,

    [int]$Depth = 14,

    [switch]$KeepArtifacts
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Normalize-MountPoint {
    param([string]$Value)

    if ($Value.EndsWith("\")) {
        return $Value.TrimEnd("\")
    }
    return $Value
}

function Assert-True {
    param(
        [bool]$Condition,
        [string]$Message
    )

    if (-not $Condition) {
        throw $Message
    }
}

function Assert-FileText {
    param(
        [string]$Path,
        [string]$Expected
    )

    Assert-True (Test-Path -LiteralPath $Path -PathType Leaf) "Missing file: $Path"
    $actual = [IO.File]::ReadAllText($Path)
    if ($actual -ne $Expected) {
        throw "Content mismatch for $Path"
    }
}

function New-DeterministicBytes {
    param(
        [int]$Length,
        [int]$Seed
    )

    $bytes = [byte[]]::new($Length)
    for ($i = 0; $i -lt $Length; $i++) {
        $bytes[$i] = [byte](($Seed + ($i * 31) + [Math]::Floor($i / 7)) % 256)
    }
    Write-Output -NoEnumerate $bytes
}

function Assert-FileBytes {
    param(
        [string]$Path,
        [byte[]]$Expected
    )

    Assert-True (Test-Path -LiteralPath $Path -PathType Leaf) "Missing file: $Path"
    try {
        $actual = [IO.File]::ReadAllBytes($Path)
    }
    catch {
        throw "Failed to read bytes from $Path. Expected $($Expected.Length) bytes. $($_.Exception.Message)"
    }
    if ($actual.Length -ne $Expected.Length) {
        throw "Length mismatch for $Path. Expected $($Expected.Length), got $($actual.Length)"
    }
    for ($i = 0; $i -lt $actual.Length; $i++) {
        if ($actual[$i] -ne $Expected[$i]) {
            throw "Byte mismatch for $Path at offset $i"
        }
    }
}

function Get-BackingFiles {
    param([string]$Root)

    if ([string]::IsNullOrWhiteSpace($Root) -or -not (Test-Path -LiteralPath $Root -PathType Container)) {
        return @()
    }
    return @(Get-ChildItem -LiteralPath $Root -Recurse -File -Force)
}

function Assert-PlaintextNotInBacking {
    param(
        [string]$Root,
        [string[]]$Needles
    )

    if ([string]::IsNullOrWhiteSpace($Root)) {
        Write-Host "Backing plaintext scan skipped; BackingRoot was not provided."
        return
    }

    $files = Get-BackingFiles -Root $Root
    foreach ($needle in $Needles) {
        $nameHits = @($files | Where-Object { $_.Name.Contains($needle) -or $_.FullName.Contains($needle) })
        if ($nameHits.Count -gt 0) {
            throw "Plaintext marker '$needle' appeared in backing filename: $($nameHits[0].FullName)"
        }

        foreach ($file in $files) {
            $hit = Select-String -LiteralPath $file.FullName -Pattern $needle -SimpleMatch -Quiet -ErrorAction SilentlyContinue
            if ($hit) {
                throw "Plaintext marker '$needle' appeared in backing file: $($file.FullName)"
            }
        }
    }
}

$mount = Normalize-MountPoint $MountPoint
Assert-True (Test-Path -LiteralPath $mount -PathType Container) "Mount point is not available: $MountPoint"

$runId = [Guid]::NewGuid().ToString("N")
$root = Join-Path ($mount + "\") "vaultfs-stress-$runId"
$hostTemp = Join-Path ([IO.Path]::GetTempPath()) "vaultfs-stress-$runId"
$marker = "vaultfs-stress-marker-$runId"
$longName = "Серия -Научно-популярная библиотека Айзека Азимова- в 53 книгах » Мир книг-скачать книги бесплатно.url"

Write-Host "VaultFS stress test"
Write-Host "Mount: $mount"
if ($BackingRoot) {
    Write-Host "Backing: $BackingRoot"
}
Write-Host "Run: $runId"

try {
    New-Item -Path $root -ItemType Directory | Out-Null

    Write-Host "1. Empty directory copy"
    $emptySource = Join-Path $root "empty-source"
    $emptyDest = Join-Path $hostTemp "empty-dest"
    New-Item -Path $emptySource -ItemType Directory | Out-Null
    New-Item -Path $hostTemp -ItemType Directory -Force | Out-Null
    & xcopy $emptySource $emptyDest /s /e /i | Out-Host
    if ($LASTEXITCODE -ne 0) {
        throw "xcopy empty directory failed with exit code $LASTEXITCODE"
    }
    Assert-True (Test-Path -LiteralPath $emptyDest -PathType Container) "xcopy did not create empty destination directory"

    Write-Host "2. Long Unicode create/read/rename"
    $longPath = Join-Path $root $longName
    $shortPath = Join-Path $root "1.url"
    $longText = "[InternetShortcut]`r`nURL=https://example.invalid/$marker`r`n"
    [IO.File]::WriteAllText($longPath, $longText)
    Assert-FileText -Path $longPath -Expected $longText
    Rename-Item -LiteralPath $longPath -NewName "1.url"
    Assert-FileText -Path $shortPath -Expected $longText
    Assert-True (-not (Test-Path -LiteralPath $longPath)) "Long name still exists after rename to 1.url"
    Rename-Item -LiteralPath $shortPath -NewName $longName
    Assert-FileText -Path $longPath -Expected $longText
    $upperLongPath = Join-Path $root ($longName.ToUpperInvariant())
    Assert-True (Test-Path -LiteralPath $upperLongPath -PathType Leaf) "Uppercase Unicode lookup failed"

    Write-Host "3. Deep path create/read/rename/delete"
    $deep = $root
    for ($i = 0; $i -lt $Depth; $i++) {
        $segment = "level-$('{0:D2}' -f $i)-unicode-Имя-с-пробелами"
        $deep = Join-Path $deep $segment
        New-Item -Path $deep -ItemType Directory | Out-Null
    }
    $deepFile = Join-Path $deep "deep-file-$marker.txt"
    $deepText = "deep path payload $marker"
    [IO.File]::WriteAllText($deepFile, $deepText)
    Assert-FileText -Path $deepFile -Expected $deepText
    $deepRenamed = Join-Path $deep "renamed-deep-file.txt"
    Rename-Item -LiteralPath $deepFile -NewName "renamed-deep-file.txt"
    Assert-FileText -Path $deepRenamed -Expected $deepText
    Remove-Item -LiteralPath $deepRenamed -Force
    Assert-True (-not (Test-Path -LiteralPath $deepRenamed)) "Deep renamed file still exists after delete"

    Write-Host "4. Deterministic binary file churn"
    $bulkDir = Join-Path $root "bulk"
    New-Item -Path $bulkDir -ItemType Directory | Out-Null
    $expectedByPath = @{}
    for ($i = 0; $i -lt $Iterations; $i++) {
        $name = "file-$('{0:D3}' -f $i)-long name Пример $i.bin"
        $path = Join-Path $bulkDir $name
        $length = (($i * 193) % 8192) + 1
        if (($i % 7) -eq 0) {
            $length = 0
        }
        $bytes = New-DeterministicBytes -Length $length -Seed ($i + 17)
        [IO.File]::WriteAllBytes($path, $bytes)
        $expectedByPath[$path] = $bytes
    }
    foreach ($entry in $expectedByPath.GetEnumerator()) {
        Assert-FileBytes -Path ([string]$entry.Key) -Expected ([byte[]]$entry.Value)
    }
    for ($i = 0; $i -lt $Iterations; $i += 3) {
        $old = Join-Path $bulkDir "file-$('{0:D3}' -f $i)-long name Пример $i.bin"
        $newName = "renamed-$('{0:D3}' -f $i).bin"
        $new = Join-Path $bulkDir $newName
        Rename-Item -LiteralPath $old -NewName $newName
        $expectedByPath[$new] = $expectedByPath[$old]
        $expectedByPath.Remove($old)
    }
    foreach ($entry in $expectedByPath.GetEnumerator()) {
        Assert-FileBytes -Path ([string]$entry.Key) -Expected ([byte[]]$entry.Value)
    }
    $listed = @(Get-ChildItem -LiteralPath $bulkDir -File -Force)
    Assert-True ($listed.Count -eq $Iterations) "Bulk list count mismatch. Expected $Iterations, got $($listed.Count)"

    Write-Host "5. Optional backing plaintext scan"
    Assert-PlaintextNotInBacking -Root $BackingRoot -Needles @($marker, $longName, "renamed-deep-file")

    Write-Host "Stress test passed."
}
finally {
    if (-not $KeepArtifacts) {
        Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $hostTemp -Recurse -Force -ErrorAction SilentlyContinue
    }
    else {
        Write-Host "Kept mounted artifacts: $root"
        Write-Host "Kept host artifacts: $hostTemp"
    }
}
