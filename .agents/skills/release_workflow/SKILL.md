---
name: release-workflow
description: Versioning, release gates, and tag-driven publishing for Vaultisor.
---

# Vaultisor Release Workflow

Follow these rules when the user asks to cut a release or change the release
process. Full context: `docs/RELEASE.md` and `docs/SDLC.md`.

## 1. Versioning

SemVer, where the "public API" is the **data format and IPC surface**, not the
source code:

- **major** — the DB schema or bundle format changes with no migration path;
  an IPC command is removed; the shape of its arguments or response changes;
  the set of fields covered by `meta_mac` changes.
- **minor** — new functionality, backwards compatible at the data level.
- **patch** — fixes that do not touch formats.

Update the version synchronously in 3 files, then refresh both lockfiles:

1. `package.json` → `"version": "X.Y.Z"`
2. `src-tauri/Cargo.toml` → `version = "X.Y.Z"`
3. `src-tauri/tauri.conf.json` → `"version": "X.Y.Z"`

```powershell
cargo update -w
npm i --package-lock-only
```

Also update the supported-versions table in `SECURITY.md`, the version section
in `README.md` (both languages) and `.github/release_notes.md`.
`src/lib/release.test.ts` fails if any of them lags behind.

Until the first public release, incompatible format changes ship as a minor
version without migrations (as the 5.x versions do); afterwards the major rule applies.

## 2. Gates (all blocking)

```bash
npm run lint && npm test && npm run build && cargo fmt --all -- --check && cargo clippy --workspace --all-targets --all-features -- -D warnings && cargo test --workspace --all-features -- --test-threads=2
```

Plus supply chain: `cargo deny check advisories licenses sources` and
`npm audit --audit-level=moderate`.

Environment notes: Strawberry Perl and NASM must precede Git's perl in `PATH`
(vendored OpenSSL will not build otherwise), and `npm run build` must run at
least once before `cargo test` — `tauri::generate_context!` panics without
`dist/`.

## 3. Local build

```powershell
.\build.ps1 -SkipDeps
```

Produces exactly one portable artifact: `release\Vaultisor-<version>.exe`.
The name always carries the version; older executables in `release` are removed.

## 4. Publishing

Check the workflows locally first:

```bash
actionlint
zizmor --persona pedantic .github/workflows
```

Nothing runs automatically: pushes, PRs and tags trigger no workflow.
`.github/workflows/release.yml` is started by hand; without `publish=true` it
is a dry run (checks + artifact, no release), and `publish=true` requires a tag
`vX.Y.Z` equal to the `package.json` version:

```text
checks (ci.yml, no cache) → build (read-only token, immutable artifact:
exe + SHA256SUMS.txt + build-info.json) → attest (Sigstore provenance, required)
→ publish (contents: write; verifies the artifact's SHA-256, gh release create)
```

```powershell
git tag -a vX.Y.Z -m "Vaultisor vX.Y.Z"
git push origin vX.Y.Z
gh workflow run release.yml --ref vX.Y.Z -f publish=true
gh run watch
```

Do not tag before the hardware smoke test (`docs/SMOKE-TEST-<version>.md`) has
passed. The pipeline is considered verified only after its first real GitHub run.

## 5. Code signing

**Binaries are published unsigned.** There is no Authenticode certificate and no
signing step in any workflow; integrity is verified through the published
SHA-256 checksum and `build-info.json`. Do not add signing instructions here
until a certificate actually exists.

## 6. Icon generation

```powershell
npx tauri icon path/to/square_icon.png
```
