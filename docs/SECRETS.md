# Secrets Management (local and CI)

DO NOT commit secrets into git. Use the `.env` file locally (ignored by git) and CI provider secrets for pipelines.

## Local setup

1. Copy `.env.template` to `.env` in the project root:

   ```bash
   cp .env.template .env
   ```

2. Edit `.env` and set `OPENAI_API_KEY` to your new key (do NOT paste keys into chat or commit them):

   ```text
   OPENAI_API_KEY=sk-...
   FINSEC_AI_ENABLED=true
   FINSEC_AI_BASE_URL=https://api.openai.com/v1
   ```

3. Load `.env` into your shell before running Gradle or the app.

### Bash (Git Bash / WSL)

```bash
export $(grep -v '^#' .env | xargs)
./gradlew bootRun
```

### PowerShell

```powershell
Get-Content .env | ForEach-Object {
  if (-not ($_ -match '^#') -and ($_ -match '=')) {
    $pair = $_ -split '=', 2
    [System.Environment]::SetEnvironmentVariable($pair[0].Trim(), $pair[1].Trim(), 'Process')
  }
}
.
\gradlew.bat bootRun
```

## CI (GitHub Actions)

- Store `OPENAI_API_KEY` in repository Secrets (Settings → Secrets → Actions).
- Reference it in workflows as `${{ secrets.OPENAI_API_KEY }}`.

Example snippet:

```yaml
env:
  OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
  FINSEC_AI_ENABLED: true
  FINSEC_AI_BASE_URL: https://api.openai.com/v1
```

## Notes

- Immediately rotate any key accidentally exposed publicly.
- Prefer short-lived keys or scoped service accounts where supported.
- Mask secrets in logs and avoid printing `OPENAI_API_KEY` at runtime.
