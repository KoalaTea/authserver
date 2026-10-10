# Files Created by AuthServer

Files the server writes to disk. Useful when running on a read-only filesystem (e.g. Docker)
to know which paths need to be writable.

Relative paths are resolved from the server's working directory.

| File | When | Configurable | Notes |
|---|---|---|---|
| `.authserver/authserverCA.pem` | Every startup | No | Generated CA certificate. Startup continues with a warning if it can't be written. |
| `.authserver/authserverCAPrivKey.pem` | Every startup | No | Generated CA private key. Startup continues with a warning if it can't be written. |
| Log file | Only when `--log-file` is set | `--log-file` / `AUTH_LOG_FILE` / `logging.file` | Startup fails if it can't be created. |
| Trace file | Only when `--trace-file` is set | `--trace-file` / `AUTH_TRACE_FILE` / `tracing.file` | Startup fails if it can't be created. |

`.authserver/` holds files the server creates on its own. `--log-file` and `--trace-file` are
written exactly where you point them, with missing parent directories created.

## Read-only filesystems

Mount a writable volume at `.authserver/` in the working directory, or accept the CA-file
warning. Point `--log-file` / `--trace-file` (if used) at a writable location.

The database is currently in-memory and does not write to disk.
