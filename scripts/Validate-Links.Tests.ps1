<#
.SYNOPSIS
    Suite di test di sicurezza per Validate-Links.ps1.

.DESCRIPTION
    Esegue test positivi e negativi per verificare che le regole di sicurezza
    del validatore rifiutino qualsiasi input manomesso, non sicuro o malformato.
#>
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$scriptDir = Split-Path -Parent $PSCommandPath
$validatorScript = Join-Path $scriptDir 'Validate-Links.ps1'
$tempDir = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), [System.Guid]::NewGuid().ToString('N'))
[System.IO.Directory]::CreateDirectory($tempDir) | Out-Null

$testsPassed = 0
$testsFailed = 0

function Assert-Test {
    param(
        [string]$Description,
        [scriptblock]$Block,
        [bool]$ExpectFailure = $false
    )

    Write-Host -NoNewline "Test: $Description ... "
    $failed = $false
    $errMessage = ""
    try {
        & $Block
    }
    catch {
        $failed = $true
        $errMessage = $_.ToString()
    }

    if ($ExpectFailure) {
        if ($failed) {
            Write-Host "PASS (Rifiutato correttamente: $errMessage)" -ForegroundColor Green
            $script:testsPassed++
        } else {
            Write-Host "FAIL (Avrebbe dovuto fallire ma è passato!)" -ForegroundColor Red
            $script:testsFailed++
        }
    } else {
        if (-not $failed) {
            Write-Host "PASS" -ForegroundColor Green
            $script:testsPassed++
        } else {
            Write-Host "FAIL (Errore imprevisto: $errMessage)" -ForegroundColor Red
            $script:testsFailed++
        }
    }
}

try {
    # 1. Test sul catalogo ufficiale reale
    Assert-Test -Description "Validazione catalogo ufficiale links.json" -Block {
        & $validatorScript
        if ($LASTEXITCODE -ne 0) { throw "Exit code $LASTEXITCODE" }
    }

    # Template valido di base per test negativi
    $validCatalog = @{
        'win11-23h2' = 'https://archive.org/download/test_item/it-it_windows_11_consumer_editions_version_23h2_updated_sep_2025_x64_dvd_98118d6e.iso'
        'win11-24h2' = 'https://archive.org/download/test_item/it-it_windows_11_consumer_editions_version_24h2_updated_sep_2025_x64_dvd_6d1ad20d.iso'
        'win11-25h2' = 'https://archive.org/download/test_item/26200.6584.250915-1905.25h2_ge_release_svc_refresh_CLIENT_CONSUMER_x64FRE_it-it.iso'
        'win11-ltsc' = 'https://archive.org/download/test_item/it-it_windows_11_enterprise_ltsc_2024_x64_dvd_1e8cabb6.iso'
    }

    function Run-MockValidation($hashtable) {
        $tempFile = [System.IO.Path]::Combine($tempDir, "mock-$([System.Guid]::NewGuid().ToString('N')).json")
        $json = $hashtable | ConvertTo-Json
        [System.IO.File]::WriteAllText($tempFile, $json, [System.Text.Encoding]::UTF8)
        try {
            & $validatorScript -CatalogPath $tempFile
            if ($LASTEXITCODE -ne 0) { throw "Validator returned exit code $LASTEXITCODE" }
        }
        finally {
            if (Test-Path -LiteralPath $tempFile) {
                Remove-Item -LiteralPath $tempFile -Force
            }
        }
    }

    # 2. Test negativi di sicurezza
    Assert-Test -Description "Rifiuto schema HTTP non cifrato" -ExpectFailure $true -Block {
        $t = $validCatalog.Clone()
        $t['win11-23h2'] = 'http://archive.org/download/test/image.iso'
        Run-MockValidation $t
    }

    Assert-Test -Description "Rifiuto dominio phishing/diverso da archive.org" -ExpectFailure $true -Block {
        $t = $validCatalog.Clone()
        $t['win11-24h2'] = 'https://archive.org.attacker.com/download/test/image.iso'
        Run-MockValidation $t
    }

    Assert-Test -Description "Rifiuto credenziali incorporate nell'URL" -ExpectFailure $true -Block {
        $t = $validCatalog.Clone()
        $t['win11-25h2'] = 'https://user:password@archive.org/download/test/image.iso'
        Run-MockValidation $t
    }

    Assert-Test -Description "Rifiuto porta non standard" -ExpectFailure $true -Block {
        $t = $validCatalog.Clone()
        $t['win11-ltsc'] = 'https://archive.org:8443/download/test/image.iso'
        Run-MockValidation $t
    }

    Assert-Test -Description "Rifiuto parametri di query" -ExpectFailure $true -Block {
        $t = $validCatalog.Clone()
        $t['win11-23h2'] = 'https://archive.org/download/test/image.iso?tracking=1'
        Run-MockValidation $t
    }

    Assert-Test -Description "Rifiuto estensione non .iso (es. .exe)" -ExpectFailure $true -Block {
        $t = $validCatalog.Clone()
        $t['win11-23h2'] = 'https://archive.org/download/test/payload.iso.exe'
        Run-MockValidation $t
    }

    Assert-Test -Description "Rifiuto path traversal nel percorso URL" -ExpectFailure $true -Block {
        $t = $validCatalog.Clone()
        $t['win11-23h2'] = 'https://archive.org/download/../etc/passwd.iso'
        Run-MockValidation $t
    }

    Assert-Test -Description "Rifiuto schema con chiave mancante" -ExpectFailure $true -Block {
        $t = $validCatalog.Clone()
        $t.Remove('win11-ltsc')
        Run-MockValidation $t
    }

    Assert-Test -Description "Rifiuto schema con chiave malevola imprevista" -ExpectFailure $true -Block {
        $t = $validCatalog.Clone()
        $t['win11-backdoor'] = 'https://archive.org/download/test/image.iso'
        Run-MockValidation $t
    }

    Assert-Test -Description "Rifiuto file JSON non valido o corrotto" -ExpectFailure $true -Block {
        $corruptFile = [System.IO.Path]::Combine($tempDir, "corrupt.json")
        [System.IO.File]::WriteAllText($corruptFile, "{ 'broken': json", [System.Text.Encoding]::UTF8)
        try {
            & $validatorScript -CatalogPath $corruptFile
        }
        finally {
            if (Test-Path -LiteralPath $corruptFile) { Remove-Item -LiteralPath $corruptFile -Force }
        }
    }

    Write-Output "`n============================================================"
    Write-Output "RIEPILOGO TEST: $testsPassed passati, $testsFailed falliti."
    Write-Output "============================================================"

    if ($testsFailed -gt 0) {
        exit 1
    }
    exit 0
}
finally {
    if (Test-Path -LiteralPath $tempDir) {
        Remove-Item -LiteralPath $tempDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}
