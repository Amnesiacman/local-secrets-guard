# local-secrets-guard

`local-secrets-guard` сканирует файлы на потенциальные утечки секретов для локального запуска и CI.

## Что умеет v0.1

- ищет типовые секреты по regex-паттернам (API keys, tokens, private key headers)
- сканирует файлы и директории рекурсивно
- поддерживает allowlist (`--allowlist`)
- выводит отчёт в `text` или `json`
- в `--strict` режиме возвращает код `1`, если есть находки

## Использование

```bash
python3 -m pip install -e .
local-secrets-guard . --strict
```

JSON-отчёт:

```bash
local-secrets-guard . --format json
```

С allowlist:

```bash
local-secrets-guard . --allowlist .secrets-allowlist --strict
```
