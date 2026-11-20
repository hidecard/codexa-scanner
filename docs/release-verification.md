# Release & Installer Verification (v1.1.5)

This document covers GitHub release packaging (v1.1.5) and the required clean-machine verification for Linux `.deb`, Windows `.exe`, and macOS `.dmg` artifacts.

## CI/CD and release workflow

- Workflow: `.github/workflows/build.yml`
- Permissions: top-level `contents: read`; only the `release` job has `contents: write`.
- Linux job (`ubuntu-22.04`): installs build deps + Wails + nfpm, builds app, runs `go test -race ./...` and `go vet ./...`, packages `build/bin/CodexaScanner_1.1.5_amd64.deb`, uploads artifact.
- Windows job (`windows-latest`): builds `CodexaScanner.exe`, runs `go test ./...` and `go vet ./...` (note: `-race` is not supported on `windows/386` toolchains; Linux CI provides race coverage), uploads artifact.
- macOS matrix: builds Intel (`amd64`) and Apple Silicon (`arm64`) app bundles, creates matching DMGs, and uploads both artifacts.
- Release job (tag push `v*`, e.g. `v1.1.5`): downloads artifacts, collects `.deb`/`.exe`/`.dmg` into `dist/`, publishes GitHub Release with generated notes and attached assets.

## v1.1.5 release steps (maintainers)

1. Ensure `main` is green (tests, vet, frontend build) and versioned packaging is correct (`nfpm.yaml` version `1.1.5`, DEB filename in workflow matches).
2. Create and push tag: `git tag v1.1.5 && git push origin v1.1.5`.
3. Confirm GitHub Actions builds Linux DEB + Windows EXE + both macOS DMGs and publishes release assets.
4. Perform clean-machine install/upgrade/uninstall verification (below) before announcing the release.

## Latest Threat & CVE Feed verification

1. Open Dashboard on a clean test profile and confirm no remote feed request is made until **Sync Latest CVEs** is clicked.
2. Click **Sync Latest CVEs** with network access and verify that the result status reports cached records or source warnings without exposing target history.
3. Restart with network access unavailable and confirm the cached feed remains visible. Confirm the bundled advisory matcher remains available even with an empty feed cache.
4. If a test Web Audit identifies a matching product, confirm the Dashboard can show the affected-asset badge as a prioritization signal, not a vulnerability proof.

## Clean-machine verification (required for Phase 8)

Perform on **fresh VMs/PCs** (no prior Codexa Scanner install/state unless testing upgrade path). Record OS version, artifact filename/checksum (if provided), steps, and results.

### Linux (.deb)

1. **Install:** `sudo apt install ./CodexaScanner_1.1.5_amd64.deb` (or `dpkg -i` + dependency fix). Verify app launches and core modules open.
2. **Data creation:** Run a small authorized scan/export and confirm local history is created at the user config path (typically `~/.config/CodexaScanner/history.sqlite` or OS-equivalent XDG config dir).
3. **Upgrade:** Install newer package build/version over existing install (when available). Verify app launches and **SQLite history data retention** (existing records still visible) unless explicitly documented otherwise.
4. **Uninstall:** `sudo apt remove codexa-scanner` (and/or `purge` if applicable). Verify binary removal and document whether `CodexaScanner/history.sqlite` in the user config directory is retained or removed (user data is typically retained on remove; confirm actual behavior).
5. **Dependencies:** Confirm declared dependencies (`libgtk-3-0`, `libwebkit2gtk-4.0-37` per `nfpm.yaml`) resolve on a clean supported system.

### Windows (.exe, portable artifact)

1. **Install/run:** Place `CodexaScanner.exe` on a clean Windows machine with WebView2 runtime available. Launch and verify core functionality.
2. **Data creation:** Create local history/export and confirm `CodexaScanner\history.sqlite` under the OS user config directory.
3. **Upgrade:** Replace executable with newer build. Verify app launches and history data remains in the same user config location.
4. **Uninstall/removal:** Delete executable (portable). Verify user config/history behavior as expected and document results.
5. **Installer decision:** A conventional Windows installer (MSI/Setup) is not yet shipped; add only after upgrade/uninstall behavior is defined.

### Data retention expectation

- Local history is stored in the OS user configuration directory under `CodexaScanner/history.sqlite` (not in the install directory). Upgrades that replace binaries should not delete this user-data path; uninstall behavior must be verified on clean systems and documented.
- History is local, capped, not encrypted, and subject to bounded best-effort redaction—review before sharing.

## Signatures/provenance

- Not configured in this workflow. Add signing/provenance and release checks if required by the distribution threat model.


## macOS DMG

1. Download `CodexaScanner-arm64.dmg` for Apple Silicon Macs (M-series) or `CodexaScanner-amd64.dmg` for Intel Macs.
2. Open the DMG and drag `CodexaScanner.app` to `Applications`.
3. Launch the app. Because the release is not currently code-signed or notarized, macOS may require Finder → Control-click → **Open** on first launch.
4. Run a small authorized scan and confirm local history is retained after replacing the app with the next release.

The DMG is a distribution container only; it does not install an auto-updater.
