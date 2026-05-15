## Docker Images

`ghcr.io/yat/yat:latest` tracks the `main` branch. It's just `yat`, no userland.
`ghcr.io/yat/yat:alpine-latest` also tracks `main`, but the entrypoint is a shell for easy debugging.

## Development

```
bin/dev # for hot reloads 
# or run bin/serve directly
```

The dev TLS credentials are allowed to use any path matching `local/**`, so:

```
bin/yat sub local/greetings
```

```
echo hi | bin/yat pub local/greetings
```

### Required Tools

- `mkcert` is called by various dev scripts in [`bin/`](bin) to generate local credentials

### Occasional Tools

- `buf` is required to run `(cd api && buf build)`, which generates [`internal/wire`](internal/wire)
- `ragel` is required to run `go generate .`, which compiles [`path.rl`](path.rl)

### jq for output parsing

The yat client outputs JSON with the format `{"path": "<path>", "data": "<base64-encoded data>"}`. To decode the data, you can use `jq`:

```sh
bin/yat sub local/greetings | jq '{path: .path, data: (.data | @base64d)}'
```

If the data itself is JSON, you can further parse it:

```sh
bin/yat sub local/greetings | jq '{path: .path, data: (.data | @base64d | fromjson)}'
```
