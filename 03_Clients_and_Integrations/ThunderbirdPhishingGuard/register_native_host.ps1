# PowerShell Registration Script for Thunderbird Phishing Guard Native Host
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
if (!$ScriptDir) { $ScriptDir = Get-Location }

$ManifestPath = Join-Path $ScriptDir "thunderbird_phishing_guard.json"
$BatPath = Join-Path $ScriptDir "thunderbird_phishing_guard.bat"

# 1. Update manifest JSON with the exact absolute path to the .bat file
$ManifestContent = Get-Content -Raw -Path $ManifestPath -Encoding UTF8 | ConvertFrom-Json
$ManifestContent.path = $BatPath
$ManifestContent | ConvertTo-Json -Depth 5 | Set-Content -Path $ManifestPath -Encoding UTF8

# 2. Register under both Mozilla and Thunderbird registry hives
$RegistryPaths = @(
    "HKCU:\Software\Mozilla\NativeMessagingHosts\thunderbird_phishing_guard",
    "HKCU:\Software\Thunderbird\NativeMessagingHosts\thunderbird_phishing_guard"
)

foreach ($RegPath in $RegistryPaths) {
    if (!(Test-Path $RegPath)) {
        New-Item -Path $RegPath -Force | Out-Null
    }
    Set-Item -Path $RegPath -Value $ManifestPath
    Write-Host "[+] Registered in: $RegPath" -ForegroundColor Cyan
}

Write-Host "[+] Successfully registered Thunderbird Phishing Guard Native Messaging Host!" -ForegroundColor Green
Write-Host "[+] Manifest: $ManifestPath" -ForegroundColor Gray
Write-Host "[+] Target Bat: $BatPath" -ForegroundColor Gray
