# local-secrets-guard

[English version](README.md)

Сканирование файлов на потенциальные утечки секретов перед коммитом или в CI.

## Возможности

- рекурсивный скан
- детект по regex-паттернам
- поддержка allowlist
- strict-режим для CI
- вывод в text/json

## Использование

```bash
python3 main.py . --strict
python3 main.py . --format json
python3 main.py . --allowlist .secrets-allowlist --strict
```

## Коды возврата

- `0` блокирующих находок нет
- `1` strict-режим не пройден
