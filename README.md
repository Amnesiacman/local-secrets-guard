# local-secrets-guard

[Русская версия](README.ru.md)

Scan files for potential secrets leakage before commit or in CI.

## Features

- recursive scanning
- pattern-based secret detection
- allowlist support
- strict CI mode
- text/json output

## Usage

```bash
python3 main.py . --strict
python3 main.py . --format json
python3 main.py . --allowlist .secrets-allowlist --strict
```

## Exit codes

- `0` no blocking findings
- `1` strict mode failed
