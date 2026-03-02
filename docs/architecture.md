# JuiceChain Architecture (v0.6)

## Runtime Layers

- `cli/main.py`: argument parsing, command orchestration, unified error handling.
- `core/*`: scanning modules (`alive`, `info_gather`, `enumeration`, `vulnerability`, `dom_xss`).
- `utils/logging.py`: central logging configuration and shared logger accessor.
- `utils/output.py`: unified CLI result schema and output rendering (`json`/`table`).

## Unified Result Schema

All commands emit a top-level payload:

- `meta`: tool/version/command/schema/timestamp/duration
- `ok`: command success status
- `target`: command target or input reference
- `data`: command-specific data body
- `errors`: normalized error list

Schema id:

- `juicechain.cli.result/v1`

## Logging Pipeline

- Logger namespace root: `juicechain`
- Console handler level: controlled by `--log-level`
- File handler level: always `DEBUG` when enabled
- Default file path: `.juicechain/juicechain.log`
- Log line format:
  `YYYY-MM-DD HH:MM:SS | LEVEL | module.name | message`

## Error Handling Strategy

- Recoverable operational failures are included in structured `errors`.
- CLI-level invalid input and runtime exceptions are captured and returned as structured payloads.
- Command exit code:
  - `0`: success
  - `1`: command executed but failed (runtime/module errors)
  - `2`: usage/input error
