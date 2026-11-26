param(
  [string]$Command = "help",
  [Parameter(ValueFromRemainingArguments = $true)]
  [string[]]$Rest
)

$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$Python = Join-Path $Root "env\Scripts\python.exe"
$VerifyScript = Join-Path $Root "scripts\verify.py"
$MainScript = Join-Path $Root "src\main.py"

function Fail {
  param([string]$Message)
  throw $Message
}

function Assert-Python {
  if (-not (Test-Path -LiteralPath $Python)) {
    Fail "Python environment not found at env\Scripts\python.exe"
  }
}

function Assert-Nmap {
  if (-not (Get-Command nmap -ErrorAction SilentlyContinue) -and -not (Get-Command nmap.exe -ErrorAction SilentlyContinue)) {
    Fail "Nmap not found in PATH"
  }
}

function Assert-PowerShellSyntax {
  foreach ($file in @("probe.ps1", "verify.ps1")) {
    $tokens = $null
    $errors = $null
    [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $Root $file), [ref]$tokens, [ref]$errors) | Out-Null
    if ($errors.Count -gt 0) {
      Fail "PowerShell syntax error in $file"
    }
  }
}

function Has-Option {
  param(
    [string[]]$Options,
    [string]$Name
  )
  foreach ($item in $Options) {
    if ($item -eq $Name -or $item.StartsWith("$Name=")) {
      return $true
    }
  }
  return $false
}

function Add-Option {
  param(
    [string[]]$Options,
    [string]$Flag,
    [string]$Value
  )
  if (-not (Has-Option -Options $Options -Name $Flag)) {
    $Options += @($Flag, $Value)
  }
  return $Options
}

function Invoke-Python {
  param([string[]]$PythonArgs)
  & $Python @PythonArgs
  if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
  }
}

function Show-Usage {
  Write-Host "Usage: .\probe.ps1 <command> [options]"
  Write-Host ""
  Write-Host "Commands:"
  Write-Host "  verify                 Run full build verification"
  Write-Host "  scan [options]         Scan an authorized target (defaults to localhost)"
  Write-Host "  odpc [options]         Scan with ODPC registration lookup"
  Write-Host "  check-config           Validate targets.yaml authorization rules"
  Write-Host "  check-report [file]    Validate latest or given report"
  Write-Host "  check-outputs          Validate latest scan and report"
}

$options = @($Rest)

switch ($Command.ToLowerInvariant()) {
  "verify" {
    Assert-Python
    Assert-Nmap
    Assert-PowerShellSyntax
    Invoke-Python -PythonArgs @($VerifyScript)
    break
  }
  "scan" {
    Assert-Python
    Assert-Nmap
    Invoke-Python -PythonArgs @($VerifyScript, "--check-config")
    $options = Add-Option -Options $options -Flag "--target" -Value "localhost"
    $options = Add-Option -Options $options -Flag "--timeout" -Value "60"
    Invoke-Python -PythonArgs (@($MainScript) + $options)
    break
  }
  "odpc" {
    Assert-Python
    Assert-Nmap
    Invoke-Python -PythonArgs @($VerifyScript, "--check-config")
    if (-not (Has-Option -Options $options -Name "--register-file")) {
      Fail "odpc requires --register-file"
    }
    $options = Add-Option -Options $options -Flag "--target" -Value "localhost"
    $options = Add-Option -Options $options -Flag "--timeout" -Value "60"
    Invoke-Python -PythonArgs (@($MainScript) + $options)
    break
  }
  "check-config" {
    Assert-Python
    Invoke-Python -PythonArgs @($VerifyScript, "--check-config")
    break
  }
  "check-report" {
    Assert-Python
    if ($options.Count -gt 0) {
      Invoke-Python -PythonArgs @($VerifyScript, "--check-report", $options[0])
    } else {
      Invoke-Python -PythonArgs @($VerifyScript, "--check-report")
    }
    break
  }
  "check-outputs" {
    Assert-Python
    Invoke-Python -PythonArgs @($VerifyScript, "--check-outputs")
    break
  }
  "help" {
    Show-Usage
    break
  }
  default {
    Show-Usage
    Fail "Unknown command: $Command"
  }
}
