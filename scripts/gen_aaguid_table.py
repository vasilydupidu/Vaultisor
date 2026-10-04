"""Генерация таблицы моделей FIDO2-ключей из FIDO Metadata Service (MDS3).

Зачем скрипт, а не таблица вручную: прежняя таблица была написана по памяти,
и из восьми записей шесть расходились с реестром. В том числе ключ
YubiKey 5 Series with NFC показывался как «YubiKey 5 NFC FIPS» — ложное
утверждение о сертификации в продукте, который про безопасность, — а AAGUID
Feitian iePass был подписан «Рутокен MFA».

Название модели используется только как имя ключа по умолчанию, когда
пользователь его не задал. Поэтому подпись JWT здесь не проверяется: на
безопасность таблица не влияет, а поддельное имя в худшем случае окажется
неточной подписью. Решения о доверии ключу принимаются по криптографии
(PRF, флаг UV в подписанных authenticator data), а не по имени.

Запуск вручную, не при сборке: сборка должна оставаться офлайновой и
воспроизводимой, поэтому результат коммитится.

    python scripts/gen_aaguid_table.py            # скачать свежий MDS
    python scripts/gen_aaguid_table.py blob.jwt   # из сохранённого файла

MDS ограничивает частоту запросов, поэтому второй вариант нужен не только
для офлайна: повторный запуск подряд получает HTTP 429.
"""

import base64
import json
import pathlib
import sys
import urllib.request

MDS_URL = "https://mds3.fidoalliance.org/"
OUT = pathlib.Path(__file__).resolve().parent.parent / "src-tauri" / "src" / "auth" / "aaguid_table.rs"


def main() -> None:
    if len(sys.argv) > 1:
        raw = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8").strip()
    else:
        raw = urllib.request.urlopen(MDS_URL, timeout=120).read().decode().strip()
    payload = raw.split(".")[1]
    blob = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))

    rows = {}
    for entry in blob["entries"]:
        aaguid = entry.get("aaguid")
        if not aaguid:
            continue  # U2F-only устройства идентифицируются иначе
        name = entry["metadataStatement"].get("description", "").strip()
        if name:
            rows[aaguid.replace("-", "").lower()] = name

    lines = [
        "// @generated scripts/gen_aaguid_table.py — не редактировать вручную.",
        f"// Источник: FIDO Metadata Service, выпуск №{blob.get('no')}, следующее обновление {blob.get('nextUpdate')}.",
        "//",
        "// Имена взяты из реестра дословно. Отсутствие ключа в таблице — не ошибка:",
        "// часть производителей, в том числе Рутокен, в MDS не зарегистрирована.",
        "",
        "/// AAGUID (hex без дефисов, нижний регистр) → название модели по MDS.",
        "/// Отсортировано по AAGUID для двоичного поиска.",
        "pub(crate) static AAGUID_MODELS: &[(&str, &str)] = &[",
    ]
    for aaguid in sorted(rows):
        name = rows[aaguid].replace("\\", "\\\\").replace('"', '\\"')
        lines.append(f'    ("{aaguid}", "{name}"),')
    lines.append("];")
    lines.append("")

    OUT.write_text("\n".join(lines), encoding="utf-8")
    print(f"записано {len(rows)} моделей из MDS №{blob.get('no')} в {OUT}")


if __name__ == "__main__":
    main()
