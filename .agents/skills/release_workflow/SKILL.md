---
name: release-workflow
description: Automated release, versioning, SignPath code signing, and deployment guide for Vaultisor.
---

# Vaultisor Release & Code Signing Workflow

When the user asks to release a new version, update release process, or manage SignPath code signing, follow these exact rules:

## 1. Versioning Standard
Update version numbers synchronously across 3 files:
1. `package.json` -> `"version": "X.Y.Z"`
2. `src-tauri/Cargo.toml` -> `version = "X.Y.Z"`
3. `src-tauri/tauri.conf.json` -> `"version": "X.Y.Z"`

## 2. Triggering Automated Release with SignPath Code Signing
Pushing a tag starting with `v` (e.g., `v2.6.0`) triggers `.github/workflows/release.yml`.

Commands:
```powershell
$env:GIT_EDITOR="true"
git add .
git commit -m "release: bump version to v2.6.0"
git push origin main
git push origin :refs/tags/v2.6.0
git tag -f -a v2.6.0 -m "Vaultisor v2.6.0 Release"
git push origin v2.6.0
```

## 3. SignPath Configuration Details
- **Organization ID**: `74269e6a-1f6c-4238-84bd-122b7e750f56`
- **Project Slug**: `vaultisor`
- **Signing Policy Slug**: `release-signing`
- **Module**: `SignPath` PowerShell module (`Submit-SigningRequest`)
- **GitHub Secrets required**: `SIGNPATH_API_TOKEN`, `SIGNPATH_ORGANIZATION_ID`

## 4. Icon Generation
```powershell
npx tauri icon path/to/square_icon.png
```
