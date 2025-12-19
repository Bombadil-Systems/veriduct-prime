# Sentinel

Detects Veriduct artifacts in SQLite databases.

## Usage

```bash
python sentinel.py database.db
python sentinel.py *.db
python sentinel.py -q database.db  # quiet mode
```

## Exit Codes

- 0: Clean
- 1: Suspicious
- 2: Veriduct detected

## Limitations

Detects the reference implementation. Modified configurations may not be detected.
