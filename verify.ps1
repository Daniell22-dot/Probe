param(
  [Parameter(ValueFromRemainingArguments = $true)]
  [string[]]$Rest
)

$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
& (Join-Path $Root "probe.ps1") verify @Rest
exit $LASTEXITCODE
