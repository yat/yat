//go:build !human

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"yat.io/yat"
	"yat.io/yat/cmd"
)

const cliTestTimeout = 5 * time.Second

var cliStateMu sync.Mutex

func TestCLIHelpUsageAndSeed(t *testing.T) {
	h := newCLIHarness(t)

	h.run("help").mustSucceed(t).stdoutContains(t, "Yat is a message bus.")
	h.run("help", "req").mustSucceed(t).stdoutContains(t, "yat post PATH")
	h.run("help", "post", "-log-level", "debug").mustSucceed(t).stdoutContains(t, "yat post PATH")
	h.run("help", "serve").mustSucceed(t).stdoutContains(t, "The server requires a TLS certificate and key.")
	h.run().mustFail(t).stderrContains(t, "usage: yat [flags] COMMAND [args]")
	h.run("bogus").mustFail(t).stderrContains(t, "yat bogus: unknown command")

	h.seed(t)
	for _, name := range []string{"tls.crt", "tls.key", "ca.crt", "rules.yaml"} {
		if _, err := os.Stat(filepath.Join(h.seedDir, name)); err != nil {
			t.Fatalf("seed file %s: %v", name, err)
		}
	}
}

func TestCLIHelpFlags(t *testing.T) {
	h := newCLIHarness(t)

	cases := []struct {
		name string
		args []string
		want string
	}{
		{
			name: "short_top_level",
			args: []string{"-h"},
			want: "Yat is a message bus.",
		},
		{
			name: "long_top_level",
			args: []string{"-help"},
			want: "Yat is a message bus.",
		},
		{
			name: "question_top_level",
			args: []string{"-?"},
			want: "Yat is a message bus.",
		},
		{
			name: "publish",
			args: []string{"publish", "-h"},
			want: "yat publish PATH",
		},
		{
			name: "post",
			args: []string{"post", "-help"},
			want: "yat post PATH",
		},
		{
			name: "subscribe",
			args: []string{"subscribe", "-?"},
			want: "yat subscribe PATH",
		},
		{
			name: "handle",
			args: []string{"handle", "-h"},
			want: "yat handle PATH",
		},
		{
			name: "seed",
			args: []string{"seed", "-help"},
			want: "yat seed DIR",
		},
		{
			name: "serve",
			args: []string{"serve", "-?"},
			want: "yat serve",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h.run(tc.args...).mustSucceed(t).stdoutContains(t, tc.want)
		})
	}
}

func TestCLIUsageAndArgumentErrors(t *testing.T) {
	h := newCLIHarness(t)

	cases := []struct {
		name string
		args []string
		env  []string
		want string
	}{
		{
			name: "no_command",
			want: "usage: yat [flags] COMMAND [args]",
		},
		{
			name: "global_flag_without_command",
			args: []string{"-log-level", "debug"},
			want: "usage: yat [flags] COMMAND [args]",
		},
		{
			name: "bad_global_flag",
			args: []string{"-wat"},
			want: "flag provided but not defined: -wat",
		},
		{
			name: "bad_command_flag",
			args: []string{"pub", "-wat", "topic"},
			want: "flag provided but not defined: -wat",
		},
		{
			name: "bad_log_level",
			args: []string{"-log-level", "nope", "help"},
			want: "invalid value",
		},
		{
			name: "unknown_command",
			args: []string{"wat"},
			want: "yat wat: unknown command",
		},
		{
			name: "help_too_many_args",
			args: []string{"help", "post", "extra"},
			want: "usage: yat help [topic]",
		},
		{
			name: "help_unknown_topic",
			args: []string{"help", "wat"},
			want: "yat help wat: unknown topic",
		},
		{
			name: "publish_no_path",
			args: []string{"publish"},
			want: "usage: yat publish PATH",
		},
		{
			name: "publish_too_many_args",
			args: []string{"publish", "one", "two"},
			want: "usage: yat publish PATH",
		},
		{
			name: "publish_bad_path",
			args: []string{"publish", "bad//path", "-empty"},
			want: "invalid path",
		},
		{
			name: "publish_wild_path",
			args: []string{"publish", "-empty", "**"},
			env:  []string{"YAT_SERVER=localhost:1"},
			want: "wild path",
		},
		{
			name: "publish_wild_inbox",
			args: []string{"publish", "topic", "-empty", "-inbox", "**"},
			env:  []string{"YAT_SERVER=localhost:1"},
			want: "wild inbox path",
		},
		{
			name: "publish_server_not_configured",
			args: []string{"publish", "topic", "-empty"},
			want: "server is not configured",
		},
		{
			name: "post_no_path",
			args: []string{"post"},
			want: "usage: yat request PATH",
		},
		{
			name: "request_too_many_args",
			args: []string{"request", "one", "two"},
			want: "usage: yat request PATH",
		},
		{
			name: "post_bad_path",
			args: []string{"post", "bad//path", "-empty"},
			want: "invalid path",
		},
		{
			name: "post_wild_path",
			args: []string{"post", "-empty", "**"},
			env:  []string{"YAT_SERVER=localhost:1"},
			want: "wild path",
		},
		{
			name: "post_negative_limit",
			args: []string{"post", "topic", "-empty", "-limit", "-1"},
			env:  []string{"YAT_SERVER=localhost:1"},
			want: "negative limit",
		},
		{
			name: "post_server_not_configured",
			args: []string{"post", "topic", "-empty"},
			want: "server is not configured",
		},
		{
			name: "subscribe_no_path",
			args: []string{"subscribe"},
			want: "usage: yat subscribe PATH",
		},
		{
			name: "sub_too_many_args",
			args: []string{"sub", "one", "two"},
			want: "usage: yat subscribe PATH",
		},
		{
			name: "subscribe_bad_path",
			args: []string{"subscribe", "bad//path"},
			env:  []string{"YAT_SERVER=localhost:1"},
			want: "invalid path",
		},
		{
			name: "subscribe_postbox_path",
			args: []string{"subscribe", "@postbox"},
			env:  []string{"YAT_SERVER=localhost:1"},
			want: "invalid postbox",
		},
		{
			name: "subscribe_server_not_configured",
			args: []string{"subscribe", "topic"},
			want: "server is not configured",
		},
		{
			name: "handle_no_path",
			args: []string{"handle"},
			want: "usage: yat respond PATH",
		},
		{
			name: "res_too_many_args",
			args: []string{"res", "one", "two"},
			want: "usage: yat respond PATH",
		},
		{
			name: "handle_bad_path",
			args: []string{"handle", "bad//path", "-empty"},
			want: "invalid path",
		},
		{
			name: "handle_postbox_path",
			args: []string{"handle", "@postbox", "-empty"},
			env:  []string{"YAT_SERVER=localhost:1"},
			want: "invalid postbox",
		},
		{
			name: "handle_server_not_configured",
			args: []string{"handle", "topic", "-empty"},
			want: "server is not configured",
		},
		{
			name: "seed_no_dir",
			args: []string{"seed"},
			want: "usage: yat seed DIR",
		},
		{
			name: "seed_too_many_args",
			args: []string{"seed", "one", "two"},
			want: "usage: yat seed DIR",
		},
		{
			name: "serve_extra_arg",
			args: []string{"serve", "extra"},
			want: "usage: yat serve",
		},
		{
			name: "serve_missing_tls",
			args: []string{"serve"},
			want: "missing TLS credentials",
		},
		{
			name: "tls_cert_without_key",
			args: []string{"serve", "-tls-cert-file", "tls.crt"},
			want: "-tls-cert-file and -tls-key-file must be set together",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h.runWithEnv(nil, tc.env, tc.args...).mustFail(t).stderrContains(t, tc.want)
		})
	}
}

func TestCLIPublishSubscribeRoundTrip(t *testing.T) {
	h := newCLIHarness(t)
	h.startServer(t)

	payload := h.writeFile(t, "publish.txt", "hello from cli")
	sub := h.start(t, nil, nil,
		h.clientArgs("sub", "cli/pub", "-n", "1")...)
	defer sub.cancel()

	result := waitForProcessAfter(t, sub, func() cliResult {
		return h.runWithEnv(nil, nil,
			h.clientArgs("pub", "cli/pub", "-file", payload, "-inbox", "cli/reply")...)
	})
	result.mustSucceed(t)

	var msg struct {
		Path  string `json:"path"`
		Inbox string `json:"inbox"`
		Data  []byte `json:"data"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(result.stdout), &msg); err != nil {
		t.Fatalf("decode subscribe output %q: %v", result.stdout, err)
	}
	if msg.Path != "cli/pub" || msg.Inbox != "cli/reply" || string(msg.Data) != "hello from cli" {
		t.Fatalf("subscribe output = path:%q inbox:%q data:%q", msg.Path, msg.Inbox, msg.Data)
	}

	rawSub := h.start(t, nil, nil,
		h.clientArgs("sub", "cli/raw", "-raw", "-n", "1")...)
	defer rawSub.cancel()

	rawResult := waitForProcessAfter(t, rawSub, func() cliResult {
		return h.runWithEnv([]byte("raw cli data"), nil,
			h.clientArgs("pub", "cli/raw")...)
	})
	rawResult.mustSucceed(t)
	if string(rawResult.stdout) != "raw cli data" {
		t.Fatalf("raw subscribe stdout = %q", rawResult.stdout)
	}
}

func TestCLIPostHandleRoundTrip(t *testing.T) {
	h := newCLIHarness(t)
	h.startServer(t)

	resFile := h.writeFile(t, "response.txt", "response data")

	handle := h.start(t, nil, nil,
		h.clientArgs("res", "cli/request", "-file", resFile, "-n", "1")...)
	defer handle.cancel()

	var post cliResult
	deadline := time.After(cliTestTimeout)
	for {
		select {
		case <-deadline:
			t.Fatalf("timed out waiting for handler readiness; last post stderr:\n%s\nhandler stderr:\n%s",
				post.stderr, handle.stderr())
		default:
		}

		post = h.runWithEnv([]byte("request data"), nil,
			h.clientArgs("req", "cli/request", "-raw", "-limit", "1")...)
		if post.err == nil {
			break
		}
		if !bytes.Contains(post.stderr, []byte("no handler for post")) {
			post.mustSucceed(t)
		}
		time.Sleep(20 * time.Millisecond)
	}

	if string(post.stdout) != "response data" {
		t.Fatalf("post stdout = %q", post.stdout)
	}

	handle.wait(t, cliTestTimeout).mustSucceed(t)
}

func TestCLIPostDuration(t *testing.T) {
	h := newCLIHarness(t)
	h.startServer(t)

	yc := h.newClient(t)
	defer yc.Close()

	handlerCtx, cancelHandler := context.WithCancel(context.Background())
	defer cancelHandler()

	handled := make(chan struct{}, 1)
	sub, err := yc.Handle(handlerCtx, yat.Sel{Path: yat.NewPath("cli/slow")}, func(ctx context.Context, _ yat.Path, _ []byte) []byte {
		select {
		case handled <- struct{}{}:
		default:
		}

		<-ctx.Done()
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		cancelHandler()
		waitCLISubDone(t, sub)
	}()

	start := time.Now()
	result := h.runWithEnv(nil, nil,
		h.clientArgs("post", "cli/slow", "-empty", "-duration", "20ms", "-timeout", "200ms")...)
	elapsed := time.Since(start)

	result.mustSucceed(t)
	if len(result.stdout) != 0 {
		t.Fatalf("post -duration stdout = %q", result.stdout)
	}
	if elapsed > 150*time.Millisecond {
		t.Fatalf("post -duration elapsed = %s, want duration-limited return", elapsed)
	}

	select {
	case <-handled:
	case <-time.After(cliTestTimeout):
		t.Fatal("handler did not receive post")
	}
}

func TestCLIDurationsAndErrors(t *testing.T) {
	h := newCLIHarness(t)
	h.startServer(t)

	h.runWithEnv(nil, nil,
		h.clientArgs("sub", "cli/quiet", "-duration", "20ms")...).mustSucceed(t)
	h.runWithEnv(nil, nil,
		h.clientArgs("res", "cli/quiet", "-empty", "-duration", "20ms")...).mustSucceed(t)
	h.runWithEnv(nil, nil,
		h.clientArgs("req", "cli/no-handler", "-empty", "-timeout", "1s")...).mustFail(t).
		stderrContains(t, "no handler for post")
}

func TestCLITokenSources(t *testing.T) {
	h := newCLIHarness(t)
	h.seed(t)

	issuer := newCLITestAuthIssuer(t)
	rulesFile := h.writeFile(t, "jwt-rules.yaml", fmt.Sprintf(`apiVersion: yat.io/v1alpha1
kind: RuleSet

rules:
  - jwt:
      iss: %q
      aud: yat-client
      sub: writer
    grants:
      - paths: ["cli/token"]
        actions: [pub]
`, issuer.url))

	server := h.start(t, nil, nil,
		"serve",
		"-bind", "127.0.0.1:0",
		"-config", rulesFile,
		"-tls-cert-file", filepath.Join(h.seedDir, "tls.crt"),
		"-tls-key-file", filepath.Join(h.seedDir, "tls.key"))
	h.waitForServer(t, server)

	writerToken := issuer.rawToken(t, "writer")
	deniedToken := issuer.rawToken(t, "denied")
	writerTokenFile := h.writeFile(t, "writer.jwt", writerToken)

	h.runWithEnv(nil, []string{"YAT_TOKEN=" + writerToken},
		h.clientArgs("pub", "cli/token", "-empty")...).mustSucceed(t)

	h.runWithEnv(nil, []string{"YAT_TOKEN=" + deniedToken},
		h.clientArgs("pub", "cli/token", "-empty", "-token-file", writerTokenFile)...).mustSucceed(t)
}

func TestCLIRuleSetScalarExpr(t *testing.T) {
	h := newCLIHarness(t)
	h.seed(t)

	issuer := newCLITestAuthIssuer(t)
	rulesFile := h.writeFile(t, "jwt-expr-rules.yaml", fmt.Sprintf(`apiVersion: yat.io/v1alpha1
kind: RuleSet

rules:
  - jwt:
      iss: %q
      aud: yat-client
    expr: '"group@example.com" in claims.groups'
    grants:
      - paths: ["cli/expr"]
        actions: [pub]
`, issuer.url))

	server := h.start(t, nil, nil,
		"serve",
		"-bind", "127.0.0.1:0",
		"-config", rulesFile,
		"-tls-cert-file", filepath.Join(h.seedDir, "tls.crt"),
		"-tls-key-file", filepath.Join(h.seedDir, "tls.key"))
	h.waitForServer(t, server)

	adminToken := issuer.rawTokenWithClaims(t, "admin", map[string]any{
		"groups": []string{"group@example.com"},
	})
	deniedToken := issuer.rawTokenWithClaims(t, "developer", map[string]any{
		"groups": []string{"other@example.com"},
	})

	h.runWithEnv(nil, []string{"YAT_TOKEN=" + adminToken},
		h.clientArgs("pub", "cli/expr", "-empty")...).mustSucceed(t)

	h.runWithEnv(nil, []string{"YAT_TOKEN=" + deniedToken},
		h.clientArgs("pub", "cli/expr", "-empty")...).mustFail(t).
		stderrContains(t, "permission denied")
}

type cliHarness struct {
	dir        string
	seedDir    string
	server     string
	stdout     *os.File
	stderr     *os.File
	stdoutPath string
	stderrPath string
}

func newCLIHarness(t *testing.T) *cliHarness {
	t.Helper()

	cliStateMu.Lock()
	t.Cleanup(cliStateMu.Unlock)

	dir := t.TempDir()

	stdoutPath := filepath.Join(dir, "stdout")
	stdout, err := os.Create(stdoutPath)
	if err != nil {
		t.Fatal(err)
	}

	stderrPath := filepath.Join(dir, "stderr")
	stderr, err := os.Create(stderrPath)
	if err != nil {
		stdout.Close()
		t.Fatal(err)
	}

	oldWD, err := os.Getwd()
	if err != nil {
		stdout.Close()
		stderr.Close()
		t.Fatal(err)
	}

	oldStdin := os.Stdin
	oldStdout := os.Stdout
	oldStderr := os.Stderr
	restoreEnv := clearYATEnv()

	os.Stdout = stdout
	os.Stderr = stderr
	if err := os.Chdir(dir); err != nil {
		os.Stdin = oldStdin
		os.Stdout = oldStdout
		os.Stderr = oldStderr
		restoreEnv()
		stdout.Close()
		stderr.Close()
		t.Fatal(err)
	}

	t.Cleanup(func() {
		os.Stdin = oldStdin
		os.Stdout = oldStdout
		os.Stderr = oldStderr
		os.Chdir(oldWD)
		restoreEnv()
		stdout.Close()
		stderr.Close()
	})

	return &cliHarness{
		dir:        dir,
		seedDir:    filepath.Join(dir, "seed"),
		stdout:     stdout,
		stderr:     stderr,
		stdoutPath: stdoutPath,
		stderrPath: stderrPath,
	}
}

func clearYATEnv() func() {
	old := map[string]string{}
	for _, kv := range os.Environ() {
		key, value, _ := strings.Cut(kv, "=")
		if !strings.HasPrefix(key, "YAT_") {
			continue
		}

		old[key] = value
		os.Unsetenv(key)
	}

	return func() {
		clearYATEnvKeys()
		for key, value := range old {
			os.Setenv(key, value)
		}
	}
}

func clearYATEnvKeys() {
	for _, kv := range os.Environ() {
		key, _, _ := strings.Cut(kv, "=")
		if strings.HasPrefix(key, "YAT_") {
			os.Unsetenv(key)
		}
	}
}

func (h *cliHarness) seed(t *testing.T) {
	t.Helper()
	h.run("seed", h.seedDir).mustSucceed(t)
}

func (h *cliHarness) startServer(t *testing.T) {
	t.Helper()

	h.seed(t)

	server := h.start(t, nil, nil,
		"serve",
		"-bind", "127.0.0.1:0",
		"-config", filepath.Join(h.seedDir, "rules.yaml"),
		"-tls-cert-file", filepath.Join(h.seedDir, "tls.crt"),
		"-tls-key-file", filepath.Join(h.seedDir, "tls.key"),
		"-tls-ca-file", filepath.Join(h.seedDir, "ca.crt"))

	h.waitForServer(t, server)
}

func (h *cliHarness) waitForServer(t *testing.T, server *cliProcess) {
	t.Helper()

	deadline := time.After(cliTestTimeout)
	for h.server == "" {
		select {
		case err := <-server.done:
			result := server.result(err)
			t.Fatalf("server exited before readiness: %v\nstdout:\n%s\nstderr:\n%s",
				err, result.stdout, result.stderr)

		case <-deadline:
			server.cancel()
			result := server.wait(t, cliTestTimeout)
			t.Fatalf("timed out waiting for server readiness\nstdout:\n%s\nstderr:\n%s",
				result.stdout, result.stderr)

		default:
			if addr := h.serveAddr(server.errOff); addr != "" {
				h.server = addr
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
	}

	t.Cleanup(func() {
		server.cancel()
		server.wait(t, cliTestTimeout).mustSucceed(t)
	})
}

func (h *cliHarness) serveAddr(off int64) string {
	for _, line := range bytes.Split(h.readSince(h.stderr, h.stderrPath, off), []byte("\n")) {
		var event struct {
			Msg  string `json:"msg"`
			Addr string `json:"addr"`
		}
		if err := json.Unmarshal(line, &event); err == nil && event.Msg == "serve" && event.Addr != "" {
			return event.Addr
		}
	}

	return ""
}

func (h *cliHarness) clientArgs(args ...string) []string {
	prefix := []string{
		"-log-level", "error",
		"-server", h.server,
		"-tls-ca-file", filepath.Join(h.seedDir, "ca.crt"),
		"-tls-cert-file", filepath.Join(h.seedDir, "tls.crt"),
		"-tls-key-file", filepath.Join(h.seedDir, "tls.key"),
	}

	return append(prefix, args...)
}

func (h *cliHarness) newClient(t *testing.T) *yat.Client {
	t.Helper()

	cfg := cmd.Config{
		TLSFiles: cmd.TLSFiles{
			CertFile: filepath.Join(h.seedDir, "tls.crt"),
			KeyFile:  filepath.Join(h.seedDir, "tls.key"),
			CAFiles:  []string{filepath.Join(h.seedDir, "ca.crt")},
		},
		Server: h.server,
	}

	client, err := cfg.NewClient(context.Background(), slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}

	return client
}

func waitCLISubDone(t *testing.T, sub yat.Sub) {
	t.Helper()

	select {
	case <-sub.Done():
	case <-time.After(cliTestTimeout):
		t.Fatal("timed out waiting for subscription")
	}
}

func (h *cliHarness) writeFile(t *testing.T, name, data string) string {
	t.Helper()

	path := filepath.Join(h.dir, name)
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func (h *cliHarness) run(args ...string) cliResult {
	return h.runWithEnv(nil, nil, args...)
}

func (h *cliHarness) runWithEnv(stdin []byte, env []string, args ...string) cliResult {
	proc := h.start(nil, stdin, env, args...)
	return proc.wait(nil, cliTestTimeout)
}

func (h *cliHarness) start(t *testing.T, stdin []byte, env []string, args ...string) *cliProcess {
	if t != nil {
		t.Helper()
	}

	h.setEnv(env)
	outOff := h.offset(h.stdout)
	errOff := h.offset(h.stderr)

	ctx, cancel := context.WithCancel(context.Background())
	proc := &cliProcess{
		h:      h,
		cancel: cancel,
		args:   append([]string(nil), args...),
		outOff: outOff,
		errOff: errOff,
		done:   make(chan error, 1),
	}

	go func() {
		restoreStdin, err := h.setStdin(stdin)
		if err != nil {
			proc.done <- err
			return
		}
		defer restoreStdin()

		err = run(ctx, args)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
		proc.done <- err
	}()

	return proc
}

func (h *cliHarness) setEnv(env []string) {
	clearYATEnvKeys()

	for _, kv := range env {
		key, value, _ := strings.Cut(kv, "=")
		os.Setenv(key, value)
	}
}

func (h *cliHarness) setStdin(stdin []byte) (func(), error) {
	if stdin == nil {
		return func() {}, nil
	}

	name := filepath.Join(h.dir, fmt.Sprintf("stdin-%d", time.Now().UnixNano()))
	if err := os.WriteFile(name, stdin, 0o600); err != nil {
		return nil, err
	}

	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}

	old := os.Stdin
	os.Stdin = f

	return func() {
		os.Stdin = old
		f.Close()
	}, nil
}

func (h *cliHarness) offset(f *os.File) int64 {
	stat, err := f.Stat()
	if err != nil {
		panic(err)
	}
	return stat.Size()
}

func (h *cliHarness) readSince(f *os.File, name string, off int64) []byte {
	_ = f.Sync()

	data, err := os.ReadFile(name)
	if err != nil {
		panic(err)
	}

	if off > int64(len(data)) {
		return nil
	}

	return data[off:]
}

func waitForProcessAfter(t *testing.T, proc *cliProcess, tick func() cliResult) cliResult {
	t.Helper()

	deadline := time.After(cliTestTimeout)
	for {
		select {
		case <-deadline:
			proc.cancel()
			result := proc.wait(t, cliTestTimeout)
			t.Fatalf("timed out waiting for process\nstdout:\n%s\nstderr:\n%s",
				result.stdout, result.stderr)

		case err := <-proc.done:
			return proc.result(err)

		default:
			tick().mustSucceed(t)
			time.Sleep(20 * time.Millisecond)
		}
	}
}

type cliProcess struct {
	h      *cliHarness
	cancel context.CancelFunc
	args   []string
	outOff int64
	errOff int64
	done   chan error
}

func (p *cliProcess) wait(t *testing.T, timeout time.Duration) cliResult {
	if t != nil {
		t.Helper()
	}
	defer p.cancel()

	select {
	case err := <-p.done:
		return p.result(err)

	case <-time.After(timeout):
		p.cancel()
		err := <-p.done
		result := p.result(err)
		if t != nil {
			t.Fatalf("timed out running yat %s\nstdout:\n%s\nstderr:\n%s",
				strings.Join(result.args, " "), result.stdout, result.stderr)
		}
		return result
	}
}

func (p *cliProcess) result(err error) cliResult {
	return cliResult{
		args:   p.args,
		stdout: p.h.readSince(p.h.stdout, p.h.stdoutPath, p.outOff),
		stderr: p.h.readSince(p.h.stderr, p.h.stderrPath, p.errOff),
		err:    err,
	}
}

func (p *cliProcess) stderr() []byte {
	return p.h.readSince(p.h.stderr, p.h.stderrPath, p.errOff)
}

type cliTestAuthIssuer struct {
	server *httptest.Server
	signer jose.Signer
	url    string
}

func newCLITestAuthIssuer(t *testing.T) *cliTestAuthIssuer {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	opts := (&jose.SignerOptions{}).WithType("JWT")
	opts.WithHeader("kid", "cli-auth-test")

	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.RS256,
		Key:       key,
	}, opts)
	if err != nil {
		t.Fatal(err)
	}

	jwks, err := json.Marshal(jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{{
			Key:       &key.PublicKey,
			KeyID:     "cli-auth-test",
			Use:       "sig",
			Algorithm: string(jose.RS256),
		}},
	})
	if err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	server := httptest.NewTLSServer(mux)
	oldDefaultClient := http.DefaultClient
	http.DefaultClient = server.Client()
	t.Cleanup(func() {
		http.DefaultClient = oldDefaultClient
		server.Close()
	})

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("content-type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                server.URL,
			"authorization_endpoint":                server.URL + "/auth",
			"token_endpoint":                        server.URL + "/token",
			"jwks_uri":                              server.URL + "/keys",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})

	mux.HandleFunc("/keys", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("content-type", "application/json")
		_, _ = w.Write(jwks)
	})

	return &cliTestAuthIssuer{
		server: server,
		signer: signer,
		url:    server.URL,
	}
}

func (i *cliTestAuthIssuer) rawToken(t *testing.T, subject string) string {
	t.Helper()

	return i.rawTokenWithClaims(t, subject, nil)
}

func (i *cliTestAuthIssuer) rawTokenWithClaims(t *testing.T, subject string, claims map[string]any) string {
	t.Helper()

	raw, err := jwt.Signed(i.signer).Claims(jwt.Claims{
		Issuer:   i.url,
		Subject:  subject,
		Audience: jwt.Audience{"yat-client"},
		Expiry:   jwt.NewNumericDate(time.Now().Add(time.Hour)),
		IssuedAt: jwt.NewNumericDate(time.Now()),
	}).Claims(claims).Serialize()
	if err != nil {
		t.Fatal(err)
	}

	return raw
}

type cliResult struct {
	args   []string
	stdout []byte
	stderr []byte
	err    error
}

func (r cliResult) mustSucceed(t *testing.T) cliResult {
	t.Helper()
	if r.err != nil {
		t.Fatalf("yat %s failed: %v\nstdout:\n%s\nstderr:\n%s",
			strings.Join(r.args, " "), r.err, r.stdout, r.stderr)
	}
	return r
}

func (r cliResult) mustFail(t *testing.T) cliResult {
	t.Helper()
	if r.err == nil {
		t.Fatalf("yat %s succeeded unexpectedly\nstdout:\n%s\nstderr:\n%s",
			strings.Join(r.args, " "), r.stdout, r.stderr)
	}
	return r
}

func (r cliResult) stdoutContains(t *testing.T, want string) cliResult {
	t.Helper()
	if !bytes.Contains(r.stdout, []byte(want)) {
		t.Fatalf("yat %s stdout does not contain %q\nstdout:\n%s\nstderr:\n%s",
			strings.Join(r.args, " "), want, r.stdout, r.stderr)
	}
	return r
}

func (r cliResult) stderrContains(t *testing.T, want string) cliResult {
	t.Helper()
	if !bytes.Contains(r.stderr, []byte(want)) {
		t.Fatalf("yat %s stderr does not contain %q\nstdout:\n%s\nstderr:\n%s",
			strings.Join(r.args, " "), want, r.stdout, r.stderr)
	}
	return r
}
