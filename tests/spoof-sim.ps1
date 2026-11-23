# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

<#
.SYNOPSIS
Proves the hardware-identity stage fires, on this machine's real hardware.

.DESCRIPTION
Builds the scanner twice -- with `--features spoof-sim` and without -- and
runs it against a throwaway ping.exe once per scenario. Each scenario sets
RHOOK_SPOOF_SIM so the test build alters one path's answer in memory, as an
incomplete spoofer would (see src/hwid/sim.rs), and checks the report and
the exit code. Nothing on the machine is changed.

Run it as administrator: the disk scenario needs the drive's IDENTIFY data,
which only an administrator can read. Without one it is reported as SKIP.

.PARAMETER TargetDir
Where cargo builds. Defaults to a folder under %TEMP%, so a run from a
network share does not build over the network.

.PARAMETER NoBuild
Reuse the binaries already in TargetDir.
#>
param(
    [string]$TargetDir = (Join-Path $env:TEMP 'rhook-anticheat-spoof-sim'),
    [switch]$NoBuild
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$simDir = Join-Path $TargetDir 'sim'
$plainDir = Join-Path $TargetDir 'plain'
$simExe = Join-Path $simDir 'release\rhook-anticheat.exe'
$plainExe = Join-Path $plainDir 'release\rhook-anticheat.exe'

if (-not $NoBuild) {
    $env:CARGO_NET_GIT_FETCH_WITH_CLI = 'true'
    Push-Location $repo
    try {
        foreach ($b in @(@{ Dir = $simDir; Args = @('--features', 'spoof-sim') }, @{ Dir = $plainDir; Args = @() })) {
            $env:CARGO_TARGET_DIR = $b.Dir
            & cargo build --release --quiet @($b.Args)
            if ($LASTEXITCODE -ne 0) { throw "cargo build failed ($($b.Dir))" }
        }
    } finally {
        Remove-Item Env:\CARGO_TARGET_DIR -ErrorAction SilentlyContinue
        Pop-Location
    }
}

$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)

# Every scenario: what to set, and what the hardware-identity section must
# and must not contain. Patterns are matched against that section only, so
# findings from the process checks cannot satisfy or spoil them.
$scenarios = @(
    @{ Name = 'baseline'; Sim = ''; Exit = 0
       Must = @(); MustNot = @('\[ALERT\]', 'spoof-sim: simulating') }
    @{ Name = 'smbios'; Sim = 'smbios'; Exit = 1
       Must = @('\[ALERT\] smbios: system UUID .* differs -- the firmware-table API says [0-9A-F]{2}\*+[0-9A-F]{2} .* WMI says')
       MustNot = @('\[ALERT\] (disk|nic)') }
    @{ Name = 'disk'; Sim = 'disk'; Exit = 1; NeedsAdmin = $true
       Must = @('\[ALERT\] disk \d+ .*storage descriptor reports serial \S{2}\*+\S{2} .*the drive itself says \S{2}\*+\S{2}')
       MustNot = @('\[ALERT\] (smbios|nic)') }
    @{ Name = 'mac'; Sim = 'mac'; Exit = 1
       Must = @('\[ALERT\] nic .*IP Helper reports [0-9A-F]{2}-[0-9A-F]{2}-[0-9A-F]{2}-\*\*-\*\*-[0-9A-F]{2}, NDIS reports',
                '\[WARN \] nic .*differs from the card''s own address')
       MustNot = @('\[ALERT\] (smbios|disk)') }
    @{ Name = 'cpu'; Sim = 'cpu'; Exit = 0
       Must = @('\[WARN \] cpu: .*CPUID says 0x[0-9A-F]{8}')
       MustNot = @('\[ALERT\]') }
    @{ Name = 'all'; Sim = 'smbios,disk,mac,cpu'; Exit = 1
       Must = @('spoof-sim: simulating a spoofer on smbios, disk, mac, cpu', '\[ALERT\] smbios', '\[ALERT\] nic', '\[WARN \] cpu')
       MustNot = @() }
    # The shipped build has no simulation code: the variable must do nothing.
    @{ Name = 'plain build ignores the variable'; Sim = 'smbios,disk,mac,cpu'; Exit = 0; Plain = $true
       Must = @('smbios: \d+ identity field\(s\) in 2 view\(s\) of the table, 0 disagreement\(s\)')
       MustNot = @('\[ALERT\]', 'spoof-sim') }
)

$target = Start-Process ping.exe -ArgumentList '-n', '600', '127.0.0.1' -WindowStyle Hidden -PassThru
Start-Sleep -Milliseconds 500
$failed = 0
$results = @()
try {
    foreach ($s in $scenarios) {
        if ($s.NeedsAdmin -and -not $admin) {
            $results += [pscustomobject]@{ Scenario = $s.Name; Result = 'SKIP'; Detail = 'needs administrator' }
            continue
        }
        $exe = if ($s.Plain) { $plainExe } else { $simExe }
        if ($s.Sim) { $env:RHOOK_SPOOF_SIM = $s.Sim } else { Remove-Item Env:\RHOOK_SPOOF_SIM -ErrorAction SilentlyContinue }
        $out = & $exe $target.Id 2>&1 | ForEach-Object { "$_" }
        $code = $LASTEXITCODE
        Remove-Item Env:\RHOOK_SPOOF_SIM -ErrorAction SilentlyContinue

        # The hardware-identity section: from its header to the next one.
        $start = [array]::FindIndex([string[]]$out, [Predicate[string]] { param($l) $l -match '-- hardware identity' })
        $end = if ($start -ge 0) { [array]::FindIndex([string[]]$out, $start + 1, [Predicate[string]] { param($l) $l -match '\[info \] -- ' }) } else { -1 }
        $section = if ($start -lt 0) { @() } elseif ($end -lt 0) { $out[$start..($out.Count - 1)] } else { $out[$start..($end - 1)] }

        $problems = @()
        if ($start -lt 0) { $problems += 'no hardware identity section' }
        if ($code -ne $s.Exit) { $problems += "exit $code, expected $($s.Exit)" }
        foreach ($p in $s.Must) { if (-not ($section -match $p)) { $problems += "missing: $p" } }
        foreach ($p in $s.MustNot) { if ($section -match $p) { $problems += "unexpected: $p" } }

        if ($problems.Count -eq 0) {
            $results += [pscustomobject]@{ Scenario = $s.Name; Result = 'PASS'; Detail = "exit $code" }
        } else {
            $failed++
            $results += [pscustomobject]@{ Scenario = $s.Name; Result = 'FAIL'; Detail = ($problems -join '; ') }
            Write-Host "---- $($s.Name): hardware identity section ----"
            $section | ForEach-Object { Write-Host $_ }
        }
    }
} finally {
    Remove-Item Env:\RHOOK_SPOOF_SIM -ErrorAction SilentlyContinue
    Stop-Process -Id $target.Id -Force -ErrorAction SilentlyContinue
}

$results | Format-Table -AutoSize -Wrap | Out-String -Width 200 | Write-Host
if ($failed -gt 0) {
    Write-Host "$failed scenario(s) failed"
    exit 1
}
Write-Host 'all scenarios passed'
