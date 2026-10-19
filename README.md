[60x.ai](https://60x.ai)

# Shared organization workflows

`.github/workflows/gitleaks.yml` runs the free gitleaks CLI. Call it from a private repository with `contents: read`; no license or inherited secrets are needed. Pin the reusable workflow to a reviewed commit SHA.

```yaml
name: Secret scanning
on:
  pull_request:
  merge_group:
  schedule:
    - cron: '17 4 * * 1'
  workflow_dispatch:
permissions:
  contents: read
jobs:
  secrets:
    uses: 60xAI/.github/.github/workflows/gitleaks.yml@REVIEWED_COMMIT_SHA
    with:
      full_history: ${{ github.event_name != 'pull_request' && github.event_name != 'merge_group' }}
```

The job named `secrets / gitleaks` must pass on pull requests. PR scans cover commits between the base and head, including credentials added and subsequently removed in that range. Scheduled and manual runs scan every fetched branch and tag, including deleted files in reachable history. Unreachable or server-only objects are outside the scan.

The central config extends the pinned gitleaks default rules with AI Brain `sk_live_` API keys, GCP JSON private keys, MCP refresh tokens and client secrets, and contextual agent-mail browser/access tokens. Unprefixed tokens need a recognizable assignment name. The default rules also detect private keys, provider tokens, and JSON Web Tokens. These rules cannot identify every arbitrary random string.

Caller `.gitleaks.toml`, `.gitleaksignore`, and inline `gitleaks:allow` comments cannot waive this scan. The upstream rules include their normal file and synthetic-value exclusions. Reports retain only file paths and rule IDs. Raw scan output, matches, secret values, and code snippets are never published. A scanner error fails the job.

When a scan fails, inspect the reported path privately. Assign genuine exposures to the owner of the credential and rotate under SOC2 F05. Remove the credential from current code; do not rewrite shared history. A weekly scan continues to fail for historical exposures until an explicit, reviewed exception policy exists. This workflow does not automatically waive old findings or rotate keys.

Run `PATH="<gitleaks-bin>:$PATH" python3 tests/test_secret_scan.py` to exercise the actual workflow scan step against synthetic credentials in a temporary Git repository. The gitleaks version must match the workflow. Validate workflow syntax with `actionlint`.
