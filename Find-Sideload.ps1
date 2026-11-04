<#
.SYNOPSIS
  Zoekt phantom-DLL / sideload mogelijkheden bij geinstalleerde applicaties.

.DESCRIPTION
  - verzamelt executables (Program Files x2, LOCALAPPDATA\Programs, services)
  - parse per exe de import-tabel (native PE-parse, geen modules)
  - classificeert elke import-DLL:
      PLANT-APPDIR : ontbreekt overal, appdir writable       -> dll er neerzetten
      PLANT-PATH   : ontbreekt overal, writable PATH-dir      -> via search path
      HIJACK       : staat in appdir, appdir writable         -> proxy/vervangen
      RESOLVED     : system/KnownDLL resolvet netjes (geen output)
  - matcht tegen KnownDLLs, system32/SysWOW64, autostart (services/runkeys/tasks)
  - output: console top-lijst + CSV

USAGE (op een representatieve machine/user-context, read-only + 1 csv):
  powershell -EP Bypass -File .\Find-Sideload.ps1

  proxy-generation (startpunt; x64, test de forwarders):
    .\Find-Sideload.ps1 -GenProxy phantom_naam.dll

.NOTES
  niet in de tool (bewust, handmatig):
   - runtime verify: wat laadt de app echt? -> Procmon op 1 run
   - x86 proxies: def-forwarders zijn x64-vriendelijk; x86 decorated names zelf doen
   - managed (C#) apps: resolven via probe, niet via dll search -> flag in output
   - UWP/packaged apps: buiten scope
   - ASCII-only bewust: parse't ook zonder BOM in PS 5.1
#>

[CmdletBinding()]
param(
  [string[]]$Roots = @("$env:ProgramFiles", "${env:ProgramFiles(x86)}", "$env:LOCALAPPDATA\Programs"),
  [string]$Csv = "$env:USERPROFILE\Desktop\sideload_candidates.csv",
  [int]$MaxExe = 1500,
  [int]$MaxDllName = 64,
  [string]$GenProxy = ''
)

$ErrorActionPreference = 'SilentlyContinue'

# ---------- helpers ----------

function Test-DirWritable([string]$dir) {
  if (-not (Test-Path $dir -PathType Container)) { return $false }
  $t = Join-Path $dir (".psid_" + [Guid]::NewGuid().ToString('N') + ".tmp")
  try { [IO.File]::WriteAllText($t, 'x'); Remove-Item $t -Force; return $true }
  catch { return $false }
}

function Get-PEInfo([byte[]]$b) {
  if ($b.Length -lt 0x100) { return $null }
  $peOff = [BitConverter]::ToUInt32($b, 0x3C)
  if ($peOff -le 0 -or ($peOff + 0x100) -gt $b.Length) { return $null }
  if ([BitConverter]::ToUInt32($b, $peOff) -ne 0x00004550) { return $null }   # PE\0\0

  $machine = [BitConverter]::ToUInt16($b, $peOff + 4)
  $numSec  = [BitConverter]::ToUInt16($b, $peOff + 6)
  $optSize = [BitConverter]::ToUInt16($b, $peOff + 20)
  $opt     = $peOff + 24
  if ($opt + $optSize -gt $b.Length) { return $null }
  $magic   = [BitConverter]::ToUInt16($b, $opt)
  if ($magic -ne 0x10B -and $magic -ne 0x20B) { return $null }
  $pe32p   = ($magic -eq 0x20B)

  $ddBase  = $opt + $(if ($pe32p) { 112 } else { 96 })
  $impRva  = [BitConverter]::ToUInt32($b, $ddBase + 8)        # dir 1 = imports
  $clrRva  = [BitConverter]::ToUInt32($b, $ddBase + 14 * 8)   # dir 14 = CLI (.NET)
  $expRva  = [BitConverter]::ToUInt32($b, $ddBase)            # dir 0 = exports

  $secTab = $peOff + 24 + $optSize
  $secs = @()
  for ($i = 0; $i -lt $numSec; $i++) {
    $o = $secTab + 40 * $i
    if ($o + 40 -gt $b.Length) { break }
    $vSize = [BitConverter]::ToUInt32($b, $o + 8)
    $vAddr = [BitConverter]::ToUInt32($b, $o + 12)
    $rSize = [BitConverter]::ToUInt32($b, $o + 16)
    $rAddr = [BitConverter]::ToUInt32($b, $o + 20)
    $secs += , @($vAddr, [Math]::Max($vSize, $rSize), $rAddr)
  }
  $r2o = {
    param($rva)
    foreach ($s in $secs) {
      if ($rva -ge $s[0] -and $rva -lt ($s[0] + $s[1])) { return $s[2] + ($rva - $s[0]) }
    }
    return $null
  }

  $imports = New-Object System.Collections.Generic.List[string]
  if ($impRva -gt 0) {
    $o = & $r2o $impRva
    $guard = 0
    while ($o -and $guard -lt 256) {
      $guard++
      $oft     = [BitConverter]::ToUInt32($b, $o)
      $nameRva = [BitConverter]::ToUInt32($b, $o + 12)
      if ($oft -eq 0 -and $nameRva -eq 0) { break }
      $nameOff = & $r2o $nameRva
      if ($nameOff) {
        $end = $nameOff; while ($end -lt $b.Length -and $b[$end] -ne 0) { $end++ }
        $len = [Math]::Min($end - $nameOff, $MaxDllName)
        [void]$imports.Add([Text.Encoding]::ASCII.GetString($b, $nameOff, $len))
      }
      if ($oft -eq 0) { break }
      $o += 20
    }
  }

  $exports = $null
  if ($expRva -gt 0) {
    $eo = & $r2o $expRva
    if ($eo) {
      $nFunc  = [BitConverter]::ToUInt32($b, $eo + 0x14)
      $nNames = [BitConverter]::ToUInt32($b, $eo + 0x18)
      if ($nFunc -gt 0 -and $nFunc -lt 100000) {
        $namesRva = [BitConverter]::ToUInt32($b, $eo + 0x20)
        $no = & $r2o $namesRva
        $list = New-Object System.Collections.Generic.List[string]
        if ($no) {
          $max = [Math]::Min($nNames, 5000)
          for ($i = 0; $i -lt $max; $i++) {
            $rva = [BitConverter]::ToUInt32($b, $no + 4 * $i)
            $po = & $r2o $rva
            if ($po) {
              $end = $po; while ($end -lt $b.Length -and $b[$end] -ne 0) { $end++ }
              [void]$list.Add([Text.Encoding]::ASCII.GetString($b, $po, $end - $po))
            }
          }
        }
        $exports = $list
      }
    }
  }

  return @{
    Machine   = $machine
    IsManaged = ($clrRva -ne 0)
    Imports   = $imports
    Exports   = $exports
    PE32Plus  = $pe32p
  }
}

# ---------- context ----------

Write-Host "[*] KnownDLLs + search path laden..."

$known = New-Object System.Collections.Generic.HashSet[string]
$k = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs'
if ($k) {
  foreach ($p in $k.PSObject.Properties) {
    if ($p.Name -like 'PS*') { continue }
    $v = ("$($p.Value)").ToLower()
    if ($v -notlike '*.dll') { $v += '.dll' }
    [void]$known.Add([IO.Path]::GetFileName($v))
  }
}

$sys32  = Join-Path $env:SystemRoot 'System32'
$syswow = Join-Path $env:SystemRoot 'SysWOW64'

$pathDirs = @($env:Path -split ';' | Where-Object { $_ })
$pathWritable = @{}
foreach ($d in $pathDirs) { if ($d) { $pathWritable[$d.TrimEnd('\').ToLower()] = Test-DirWritable $d } }

Write-Host "[*] autostart verzamelen (services / runkeys / scheduled tasks)..."
$autoExes = New-Object System.Collections.Generic.HashSet[string]
$autoDirs = New-Object System.Collections.Generic.HashSet[string]

function Add-Auto([string]$raw) {
  if (-not $raw) { return }
  $s = $raw.Trim()
  if ($s.StartsWith('"')) {
    $e = $s.IndexOf('"', 1); if ($e -gt 1) { $s = $s.Substring(1, $e - 1) }
  } else {
    $sp = $s.IndexOf(' '); if ($sp -gt 0) { $s = $s.Substring(0, $sp) }
  }
  if ($s -match '\.(exe|com)$') {
    $full = ([Environment]::ExpandEnvironmentVariables($s)).ToLower()
    [void]$autoExes.Add($full)
    [void]$autoDirs.Add((Split-Path $full -Parent))
  }
}

try { Get-CimInstance Win32_Service | ForEach-Object { Add-Auto $_.PathName } } catch {}

foreach ($key in 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
                 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
                 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run') {
  $v = Get-ItemProperty $key
  if ($v) { foreach ($p in $v.PSObject.Properties) { if ($p.Name -notlike 'PS*') { Add-Auto $p.Value } } }
}

try {
  Get-ScheduledTask | ForEach-Object {
    foreach ($a in $_.Actions) { if ($a.Execute) { Add-Auto $a.Execute } }
  }
} catch {}

# ---------- exes ----------

Write-Host "[*] executables verzamelen..."
$exes = New-Object System.Collections.Generic.HashSet[string]
foreach ($root in $Roots | Where-Object { Test-Path $_ }) {
  Get-ChildItem -Path $root -Recurse -Filter *.exe -Depth 6 -ErrorAction SilentlyContinue |
    ForEach-Object { [void]$exes.Add($_.FullName) }
}
foreach ($a in @($autoExes)) { if (Test-Path $a) { [void]$exes.Add($a) } }

$exes = @($exes | Select-Object -First $MaxExe)
Write-Host ("[+] {0} executables" -f $exes.Count)

# ---------- analyse ----------

Write-Host "[*] imports parsen en classificeren..."
$rows   = New-Object System.Collections.Generic.List[object]
$count  = 0

foreach ($exe in $exes) {
  $count++
  if ($count % 100 -eq 0) { Write-Host ("    {0}/{1}" -f $count, $exes.Count) }
  try {
    if ((Get-Item $exe).Length -gt 40MB) { continue }
    $b = [IO.File]::ReadAllBytes($exe)
  } catch { continue }

  $pe = Get-PEInfo $b
  if (-not $pe -or $pe.Imports.Count -eq 0) { continue }

  $dir  = (Split-Path $exe -Parent).TrimEnd('\')
  $dirW = Test-DirWritable $dir
  $isAuto = $autoExes.Contains($exe.ToLower()) -or $autoDirs.Contains($dir.ToLower())

  foreach ($imp in $pe.Imports) {
    $name = $imp.ToLower()
    if ($name -match '^(api-ms-|ext-ms-)') { continue }
    if ($name -notlike '*.dll') { continue }

    $inApp   = Test-Path (Join-Path $dir $name) -PathType Leaf
    $inSys   = (Test-Path (Join-Path $sys32 $name) -PathType Leaf) -or (Test-Path (Join-Path $syswow $name) -PathType Leaf)
    $isKnown = $known.Contains($name)

    $class = $null; $plant = ''
    if (-not $inApp -and -not $inSys -and -not $isKnown) {
      if ($dirW) { $class = 'PLANT-APPDIR'; $plant = $dir }
      else {
        foreach ($pd in $pathDirs) {
          $kk = $pd.TrimEnd('\').ToLower()
          if ($pathWritable[$kk]) { $class = 'PLANT-PATH'; $plant = $pd; break }
        }
      }
      if (-not $class) { $class = 'PHANTOM-geen-writable-plek' }
    }
    elseif ($inApp -and $dirW) { $class = 'HIJACK-appdir' }

    if ($class) {
      $rows.Add([pscustomobject]@{
        Exe         = $exe
        Dir         = $dir
        Dll         = $name
        Class       = $class
        PlantDir    = $plant
        DirWritable = $dirW
        AutoStart   = $isAuto
        Managed     = $pe.IsManaged
        Arch        = $(if ($pe.Machine -eq 0x8664) { 'x64' } elseif ($pe.Machine -eq 0x14C) { 'x86' } else { ('0x{0:X}' -f $pe.Machine) })
      })
    }
  }
}

# ---------- output ----------

$weight = @{ 'PLANT-APPDIR' = 3; 'HIJACK-appdir' = 2; 'PLANT-PATH' = 1; 'PHANTOM-geen-writable-plek' = 0 }

$view = $rows | ForEach-Object {
    [pscustomobject]@{
        Score     = $weight[$_.Class] + $(if ($_.AutoStart) { 4 } else { 0 }) + $(if ($_.DirWritable) { 1 } else { 0 })
        AutoStart = $_.AutoStart
        Klasse    = $_.Class
        Dll       = $_.Dll
        Exe       = Split-Path $_.Exe -Leaf
        Locatie   = $(if ($_.Class -like 'PLANT*' -and $_.PlantDir) { $_.PlantDir } else { $_.Dir })
    }
}

Write-Host ""
Write-Host "=== KANDIDATEN (hoogste kans eerst) ==="
$view | Sort-Object @{e = 'Score'; Descending = $true }, Dll, Exe -Unique |
    Select-Object -First 25 |
    Format-Table Score, AutoStart, Klasse, Dll, Exe, Locatie -AutoSize | Out-String -Width 220

$c = $rows | Group-Object Class
Write-Host "Totaal rijen: $($rows.Count) | " + (($c | ForEach-Object { "$($_.Name)=$($_.Count)" }) -join ', ')

Write-Host ""
Write-Host "Actie per klasse:"
Write-Host "  PLANT-APPDIR : dll (proxy) neerzetten in de map van de exe - komt eerst in de search order"
Write-Host "  HIJACK       : bestaande dll in writable appdir vervangen door proxy (forwarders!)"
Write-Host "  PLANT-PATH   : via writable PATH-map; alleen als de exe de dll nergens eerder vindt"
Write-Host "  AutoStart=True + hoge score = voorkeur;  volledige lijst in de CSV"

$rows | Export-Csv $Csv -NoTypeInformation -Encoding UTF8
Write-Host ("[+] alles in: {0}  ({1} rijen)" -f $Csv, $rows.Count)

# ---------- optioneel: proxy .def generator ----------

if ($GenProxy) {
  $src = Join-Path $sys32 $GenProxy
  if (-not (Test-Path $src)) { Write-Host "geen $src"; return }
  $b2 = [IO.File]::ReadAllBytes($src)
  $pe2 = Get-PEInfo $b2
  if (-not $pe2 -or -not $pe2.Exports) { Write-Host 'geen exports te parsen'; return }
  $def = Join-Path (Get-Location).Path ($GenProxy -replace '\.dll$', '') + '.def'
  $lines = @("LIBRARY $GenProxy", 'EXPORTS')
  foreach ($e in $pe2.Exports) { $lines += ('  {0}={1}.{0}' -f $e, $GenProxy) }
  [IO.File]::WriteAllLines($def, $lines)
  Write-Host ("[+] proxy def: {0}  (x64; test de forwarders, data-exports handmatig)" -f $def)
}
