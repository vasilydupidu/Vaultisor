# Vaultisor Release & Code Signing Guide 🛡️

Этот документ описывает полный процесс сборки, версионирования, автоматической цифровой подписи (SignPath) и публикации релизов Vaultisor на GitHub.

---

## 🚀 Как выпустить новый релиз (Автоматически)

Для выпуска новой версии достаточно выполнить 3 простых шага:

### Шаг 1. Обновить версию в 3 файлах проекта
При смене версии (например, `v2.6.0`) укажите её в:
1. `package.json` -> `"version": "2.6.0"`
2. `src-tauri/Cargo.toml` -> `version = "2.6.0"`
3. `src-tauri/tauri.conf.json` -> `"version": "2.6.0"`

### Шаг 2. Закоммитить и запушить изменения
```bash
git add .
git commit -m "release: bump version to v2.6.0"
git push origin main
```

### Шаг 3. Создать и запушить тег релиза
```bash
git tag -a v2.6.0 -m "Vaultisor v2.6.0 Release"
git push origin v2.6.0
```

После этого GitHub Actions автоматически:
1. Компилирует релизный портативный `release/Vaultisor.exe`.
2. Отправляет его на подпись в сервис **SignPath**.
3. Забирает подписанный Authenticode-сертификатом `Vaultisor.exe`.
4. Публикует подлинно подписанный релиз на странице [GitHub Releases](https://github.com/vasilydupidu/Vaultisor/releases).

---

## ⚙️ Реквизиты интеграции SignPath (уже настроены)

- **Organization ID**: `74269e6a-1f6c-4238-84bd-122b7e750f56`
- **Project Slug**: `vaultisor`
- **Signing Policy Slug**: `release-signing`
- **GitHub Secrets**:
  - `SIGNPATH_API_TOKEN` — API токен пользователя `Vasily`.
  - `SIGNPATH_ORGANIZATION_ID` — `74269e6a-1f6c-4238-84bd-122b7e750f56`.

---

## 🎨 Обновление Иконки Приложения

При изменении или обновлении логотипа приложения:
1. Сохраните квадратный PNG (например, `1024x1024`).
2. Выполните команду пересборки всех разрешениях иконки (`.ico`, `.png`, `.icns`):
```bash
npx tauri icon path/to/icon.png
```

---

## 🔑 Стандарт формата долей Шамира (Shamir Recovery Shares)

Доли восстановления Шамира при экспорте в `.txt` сохраняются в готовом однострочном формате:
```text
vaultisor-share-v1
3|20cb4271e2e517af5138ea0494370fecd2ba9db5712351c8ffefa27595d15939
```
Это позволяет пользователю выделить и скопировать долю `3|20cb...` в 1 клик.
