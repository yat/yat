
## Development

`bin/serve` runs a development server on `[::1]:8765` and `bin/yat` connects to it.

## Logging

The `yat` program logs JSON lines to stderr.
The default log level is `ERROR`: Other levels are `WARN`, `INFO`, and `DEBUG`.
Pass the `-log-level` flag or set the `YAT_LOG_LEVEL` environment variable to change the log level.
Connection and protocol logs are written at `DEBUG-1`.
