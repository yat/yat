## Development

```
bin/setup
bin/server
```

```
bin/yat sub greetings
```

```
echo hi | bin/yat pub greetings
```

### Occasional Tools

- `protoc` is required to run `go generate ./api`
- `ragel` is required to run `go generate .`, which compiles path.rl
