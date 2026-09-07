# Load .env into the current PowerShell process
$envFile = Join-Path -Path (Get-Location) -ChildPath '.env'
if (Test-Path $envFile) {
    Get-Content $envFile | ForEach-Object {
        if ($_ -and -not ($_ -match '^#') -and ($_ -match '=')) {
            $parts = $_ -split '=', 2
            $name = $parts[0].Trim()
            $value = $parts[1].Trim()
            [System.Environment]::SetEnvironmentVariable($name, $value, 'Process')
        }
    }
    Write-Host ".env loaded into current PowerShell process"
} else {
    Write-Host ".env not found; copy .env.template to .env and set values"
}
