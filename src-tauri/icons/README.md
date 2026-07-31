# Иконки приложения

В этой папке должны лежать иконки в форматах, требуемых Tauri:

- `32x32.png`
- `128x128.png`
- `128x128@2x.png` (256×256)
- `icon.ico` (Windows)
- `icon.icns` (macOS, опционально)

## Генерация из мастер-SVG

В корне проекта есть SVG-знак Vaultisor (`branding/vaultisor-mark.svg`).
Используйте Tauri CLI для автогенерации всех форматов:

```powershell
npm run tauri icon ./branding/vaultisor-mark.png
```

(Tauri CLI принимает PNG ≥ 1024×1024. Сначала экспортируйте SVG → PNG в Inkscape/Figma/любой редактор.)

После генерации удалите этот README — Tauri-bundler не возражает против лишних файлов, но папка должна остаться.
