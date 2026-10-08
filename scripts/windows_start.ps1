param(
    [ValidateSet('Check', 'Demo', 'LiveLab', 'Scan')]
    [string]$Mode = 'Check',
    [string]$Config = 'config.local.json',
    [string]$Urls = '',
    [switch]$InstallCodex,
    [switch]$Login
)
$ErrorActionPreference = 'Stop'
Set-Location (Split-Path $PSScriptRoot -Parent)
function Invoke-Checked {
    param([string]$Program, [string[]]$Arguments)
    & $Program @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$Program failed (exit $LASTEXITCODE). Check the message above." }
}
if (-not (Get-Command py -ErrorAction SilentlyContinue)) { throw 'Install Python 3.10+ with the Python launcher (py).' }
Invoke-Checked 'py' @('-3', '-c', 'import sys; assert sys.version_info >= (3,10), "Python 3.10+ required"')
if ($InstallCodex) { Invoke-Checked 'npm.cmd' @('install', '-g', '@openai/codex') }
if ($Mode -ne 'Demo') {
    if (-not (Get-Command codex.cmd -ErrorAction SilentlyContinue)) { throw 'Install Node.js LTS, then rerun with -InstallCodex.' }
    if ($Login) { Invoke-Checked 'codex.cmd' @('login') }
}
switch ($Mode) {
    'Check' {
        Invoke-Checked 'py' @('-3', '-m', 'bounty_assist', '--workspace', '.bounty-work-check', 'doctor', '--live')
    }
    'Demo' {
        Invoke-Checked 'py' @('-3', 'examples/demo_bounty.py')
        Start-Process '.\demo-output\bounty_demo.html'
    }
    'LiveLab' {
        Invoke-Checked 'py' @('-3', 'examples/demo_bounty.py', '--live')
        Start-Process '.\live-output\bounty_demo.html'
    }
    'Scan' {
        if (-not (Test-Path -LiteralPath $Config)) { throw 'Copy config.bounty.example.json to config.local.json and configure scope, sessions and policies first.' }
        Invoke-Checked 'py' @('-3', '-m', 'bounty_assist', '--workspace', '.bounty-work-check', 'doctor', '--config', $Config)
        if ($Urls) { Invoke-Checked 'py' @('-3', '-m', 'bounty_assist', 'import', $Urls) }
        Invoke-Checked 'py' @('-3', '-m', 'bounty_assist', 'run', '--config', $Config)
        Start-Process '.\reports\bounty_report.html'
    }
}
