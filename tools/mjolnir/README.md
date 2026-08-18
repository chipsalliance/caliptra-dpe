<!-- Licensed under the Apache-2.0 license -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Caliptra DPE Mjolnir Security Audit Configurations

This directory contains the Mjolnir AI-driven security audit configurations, threat models, and job specifications for the **Caliptra DPE (Dice Protection Environment)** repository.

---

## Directory Structure

- **`project.nix`**: Core repository metadata, target source extensions (`.rs`, `.go`), and link to `threat_model.md`.
- **`threat_model.md`**: Standalone security threat model capturing trust domains (Core Engine, Crypto Layer, Response Buffer, Simulator, Verification) and critical attack surfaces.
- **`jobs/`**: Job profiles defining specific audit targets and scopes:
  - `ci.nix`: Pull Request diff scanning mode (`nix run .#ci`).
  - `main.nix`: Full audit of the `main` branch (`nix run .#main`).
  - `runtime-v1.nix`: Versioned branch audit for `runtime-1.2` (`nix run .#runtime-v1`).
- **`results/`**: Output directory for generated audit artifacts (git-ignored).
- **`workspace/`**: Local analysis working directory (git-ignored).

---

## Running Audits Locally

All jobs defined in `jobs/` are automatically discovered and exposed as native Nix packages in `flake.nix`:

### 1. PR Diff Audit (CI Mode)
Scans only the code files modified between the specified base commit and head commit:

```bash
nix run .#ci -- --diff-base main --diff-head HEAD
```

### 2. Full Main Branch Audit
Performs a comprehensive discovery and analysis scan of all source files against the threat model:

```bash
nix run .#main
```

### 3. Versioned Branch Audit
Runs an audit targeted against the `runtime-1.2` branch:

```bash
nix run .#runtime-v1
```

### 4. Sync Reports to Google Cloud Storage
Syncs local audit artifacts in `tools/mjolnir/results/` to a centralized GCS bucket:

```bash
nix run .#deploy-gcs-runs -- --bucket caliptra-github-ci-caliptra-reports --output-dir ./tools/mjolnir/results
```


---

## Continuous Integration (CI)

The GitHub Actions workflow in [`.github/workflows/mjolnir_audit.yml`](../../.github/workflows/mjolnir_audit.yml) runs on pull requests targeting `main`. It executes `nix run .#ci` inside a hermetic Nix environment on self-hosted runners using Application Default Credentials (ADC) for Vertex AI access.
