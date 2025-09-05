## Logging

The `yat` program logs JSON lines to stderr.
The default log level is `ERROR`: Pass the `-log-level` flag or set the `YAT_LOG_LEVEL` environment variable to change it.
Connection lifecycle and protocol debugging messages are written at `DEBUG-1`.