//go:build !human

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
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

func TestCLIHelp(t *testing.T) {
	h := newCLIHarness(t)

	for _, tc := range []struct {
		name string
		args []string
	}{
		{"help_command", []string{"help"}},
		{"help_alias", []string{"help", "req"}},
		{"help_after_global_flag", []string{"help", "post", "-log-level", "debug"}},
		{"help_server_alias", []string{"help", "server"}},
		{"short_top_level", []string{"-h"}},
		{"long_top_level", []string{"-help"}},
		{"question_top_level", []string{"-?"}},
		{"publish", []string{"publish", "-h"}},
		{"publish_alias", []string{"pub", "-h"}},
		{"post", []string{"post", "-help"}},
		{"post_alias", []string{"req", "-h"}},
		{"subscribe", []string{"subscribe", "-?"}},
		{"subscribe_alias", []string{"sub", "-h"}},
		{"handle", []string{"handle", "-h"}},
		{"handle_alias", []string{"res", "-h"}},
		{"seed", []string{"seed", "-help"}},
		{"serve", []string{"serve", "-?"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h.run(tc.args...).mustSucceed(t)
		})
	}
}

func TestCLISeed(t *testing.T) {
	h := newCLIHarness(t)
	h.seed(t)

	for _, name := range []string{"tls.crt", "tls.key", "ca.crt", "rules.yaml"} {
		if _, err := os.Stat(filepath.Join(h.seedDir, name)); err != nil {
			t.Fatalf("seed file %s: %v", name, err)
		}
	}
}

func TestCLIUsageAndArgumentErrors(t *testing.T) {
	h := newCLIHarness(t)
	serverEnv := []string{"YAT_SERVER=localhost:1"}

	for _, tc := range []struct {
		name string
		args []string
		env  []string
	}{
		{"no_command", nil, nil},
		{"global_flag_without_command", []string{"-log-level", "debug"}, nil},
		{"bad_global_flag", []string{"-wat"}, nil},
		{"bad_command_flag", []string{"pub", "-wat", "topic"}, nil},
		{"bad_log_level", []string{"-log-level", "nope", "help"}, nil},
		{"unknown_command", []string{"wat"}, nil},
		{"help_too_many_args", []string{"help", "post", "extra"}, nil},
		{"help_unknown_topic", []string{"help", "wat"}, nil},
		{"publish_no_path", []string{"publish"}, nil},
		{"publish_too_many_args", []string{"publish", "one", "two"}, nil},
		{"publish_bad_path", []string{"publish", "bad//path", "-empty"}, nil},
		{"publish_wild_path", []string{"publish", "-empty", "**"}, serverEnv},
		{"publish_wild_inbox", []string{"publish", "topic", "-empty", "-inbox", "**"}, serverEnv},
		{"publish_missing_file", []string{"publish", "topic", "-file", "missing"}, nil},
		{"publish_server_not_configured", []string{"publish", "topic", "-empty"}, nil},
		{"post_no_path", []string{"post"}, nil},
		{"request_too_many_args", []string{"request", "one", "two"}, nil},
		{"post_bad_path", []string{"post", "bad//path", "-empty"}, nil},
		{"post_wild_path", []string{"post", "-empty", "**"}, serverEnv},
		{"post_postbox_path", []string{"post", "@postbox", "-empty"}, serverEnv},
		{"post_missing_file", []string{"post", "topic", "-file", "missing"}, nil},
		{"post_negative_limit", []string{"post", "topic", "-empty", "-limit", "-1"}, nil},
		{"post_negative_duration", []string{"post", "topic", "-empty", "-duration", "-1s"}, nil},
		{"post_negative_timeout", []string{"post", "topic", "-empty", "-timeout", "-1s"}, nil},
		{"post_duration_exceeds_timeout", []string{"post", "topic", "-empty", "-duration", "2s", "-timeout", "1s"}, nil},
		{"post_server_not_configured", []string{"post", "topic", "-empty"}, nil},
		{"subscribe_no_path", []string{"subscribe"}, nil},
		{"sub_too_many_args", []string{"sub", "one", "two"}, nil},
		{"subscribe_bad_path", []string{"subscribe", "bad//path"}, serverEnv},
		{"subscribe_postbox_path", []string{"subscribe", "@postbox"}, serverEnv},
		{"subscribe_negative_limit", []string{"subscribe", "topic", "-limit", "-1"}, serverEnv},
		{"subscribe_negative_duration", []string{"subscribe", "topic", "-duration", "-1s"}, serverEnv},
		{"subscribe_server_not_configured", []string{"subscribe", "topic"}, nil},
		{"handle_no_path", []string{"handle"}, nil},
		{"res_too_many_args", []string{"res", "one", "two"}, nil},
		{"handle_bad_path", []string{"handle", "bad//path", "-empty"}, nil},
		{"handle_postbox_path", []string{"handle", "@postbox", "-empty"}, serverEnv},
		{"handle_missing_file", []string{"handle", "topic", "-file", "missing"}, nil},
		{"handle_negative_limit", []string{"handle", "topic", "-empty", "-limit", "-1"}, nil},
		{"handle_negative_duration", []string{"handle", "topic", "-empty", "-duration", "-1s"}, nil},
		{"handle_server_not_configured", []string{"handle", "topic", "-empty"}, nil},
		{"seed_no_dir", []string{"seed"}, nil},
		{"seed_too_many_args", []string{"seed", "one", "two"}, nil},
		{"serve_extra_arg", []string{"serve", "extra"}, nil},
		{"serve_missing_tls", []string{"serve"}, nil},
		{"tls_cert_without_key", []string{"serve", "-tls-cert-file", "tls.crt"}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h.runWithEnv(nil, tc.env, tc.args...).mustFail(t)
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

	post := waitForHandlerReady(t, handle, func() cliResult {
		return h.runWithEnv([]byte("request data"), nil,
			h.clientArgs("req", "cli/request", "-raw", "-limit", "1")...)
	})
	if string(post.stdout) != "response data" {
		t.Fatalf("post stdout = %q", post.stdout)
	}
	handle.wait(t, cliTestTimeout).mustSucceed(t)

	jsonResFile := h.writeFile(t, "json-response.txt", "json response")
	handle = h.start(t, nil, nil,
		h.clientArgs("res", "cli/request-json", "-file", jsonResFile, "-n", "1")...)
	defer handle.cancel()

	post = waitForHandlerReady(t, handle, func() cliResult {
		return h.runWithEnv([]byte("request data"), nil,
			h.clientArgs("req", "cli/request-json", "-limit", "1")...)
	})

	var res yat.Res
	if err := json.Unmarshal(bytes.TrimSpace(post.stdout), &res); err != nil {
		t.Fatalf("decode post output %q: %v", post.stdout, err)
	}
	if string(res.Data) != "json response" {
		t.Fatalf("post response data = %q; stdout = %q", res.Data, post.stdout)
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
	h.runWithEnv([]byte("stdin response"), nil,
		h.clientArgs("res", "cli/stdin", "-duration", "20ms")...).mustSucceed(t)
	h.runWithEnv(nil, nil,
		h.clientArgs("req", "cli/no-handler", "-empty", "-timeout", "1s")...).mustFail(t)
}

func TestCLIServeRoot(t *testing.T) {
	h := newCLIHarness(t)
	h.startServer(t)

	status, err := h.getRootStatus(t, h.clientTLSConfig(t, true))
	if err != nil {
		t.Fatal(err)
	}

	if status != http.StatusOK {
		t.Fatalf("GET / status = %d, want %d", status, http.StatusOK)
	}
}

func TestCLIServeClientCertPolicy(t *testing.T) {
	t.Run("default_requires_client_cert", func(t *testing.T) {
		h := newCLIHarness(t)
		h.startTLSServer(t, "-tls-ca-file", filepath.Join(h.seedDir, "ca.crt"))

		if _, err := h.getRootStatus(t, h.clientTLSConfig(t, false)); err == nil {
			t.Fatal("GET / without client cert succeeded")
		}
	})

	t.Run("default_without_ca_rejects_client_cert", func(t *testing.T) {
		h := newCLIHarness(t)
		h.startTLSServer(t)

		if _, err := h.getRootStatus(t, h.clientTLSConfig(t, true)); err == nil {
			t.Fatal("GET / with unverifiable client cert succeeded")
		}
	})

	t.Run("flag_false_allows_missing_client_cert", func(t *testing.T) {
		h := newCLIHarness(t)
		h.startTLSServer(t, "-tls-require-client-cert=false")

		status, err := h.getRootStatus(t, h.clientTLSConfig(t, false))
		if err != nil {
			t.Fatal(err)
		}
		if status != http.StatusOK {
			t.Fatalf("GET / status = %d, want %d", status, http.StatusOK)
		}
	})

	t.Run("flag_false_rejects_unverifiable_client_cert", func(t *testing.T) {
		h := newCLIHarness(t)
		h.startTLSServer(t, "-tls-require-client-cert=false")

		if _, err := h.getRootStatus(t, h.clientTLSConfig(t, true)); err == nil {
			t.Fatal("GET / with unverifiable client cert succeeded")
		}
	})
}

func TestCLIServeConfigErrors(t *testing.T) {
	h := newCLIHarness(t)
	h.seed(t)

	for _, tc := range []struct {
		name string
		data string
	}{
		{"missing_file", ""},
		{"bad_yaml", "apiVersion: ["},
		{"invalid_api_version", "apiVersion: nope\nkind: RuleSet\n"},
		{"missing_kind", "apiVersion: yat.io/v1alpha1\n"},
		{"unknown_kind", "apiVersion: yat.io/v1alpha1\nkind: Wat\n"},
		{"invalid_rules_shape", "apiVersion: yat.io/v1alpha1\nkind: RuleSet\nrules: nope\n"},
		{"invalid_rule", "apiVersion: yat.io/v1alpha1\nkind: RuleSet\nrules:\n  - grants:\n      - paths: [ok]\n        actions: [wat]\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			configFile := filepath.Join(h.dir, tc.name+".yaml")
			if tc.name != "missing_file" {
				configFile = h.writeFile(t, tc.name+".yaml", tc.data)
			}

			h.run(h.serveArgs(t, "-config", configFile)...).mustFail(t)
		})
	}
}

func TestCLITokenSources(t *testing.T) {
	h := newCLIHarness(t)

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

	h.startTokenServer(t, rulesFile)

	writerToken := issuer.rawToken(t, "writer")
	deniedToken := issuer.rawToken(t, "denied")
	writerTokenFile := h.writeFile(t, "writer.jwt", "\n\t"+writerToken+"\n")

	h.runWithEnv(nil, []string{"YAT_TOKEN=" + writerToken},
		h.clientArgsNoCert("pub", "cli/token", "-empty")...).mustSucceed(t)

	h.runWithEnv(nil, []string{"YAT_TOKEN=" + deniedToken},
		h.clientArgsNoCert("pub", "cli/token", "-empty", "-token-file", writerTokenFile)...).mustSucceed(t)

	h.runWithEnv(nil, []string{"YAT_TOKEN=\n\t" + writerToken + "\n"},
		h.clientArgsNoCert("pub", "cli/token", "-empty")...).mustSucceed(t)
}

func TestCLIRuleSetScalarExpr(t *testing.T) {
	h := newCLIHarness(t)

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

	h.startTokenServer(t, rulesFile)

	adminToken := issuer.rawTokenWithClaims(t, "admin", map[string]any{
		"groups": []string{"group@example.com"},
	})
	deniedToken := issuer.rawTokenWithClaims(t, "developer", map[string]any{
		"groups": []string{"other@example.com"},
	})

	h.runWithEnv(nil, []string{"YAT_TOKEN=" + adminToken},
		h.clientArgsNoCert("pub", "cli/expr", "-empty")...).mustSucceed(t)

	h.runWithEnv(nil, []string{"YAT_TOKEN=" + deniedToken},
		h.clientArgsNoCert("pub", "cli/expr", "-empty")...).mustFail(t)
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

	h.startTLSServer(t,
		"-config", filepath.Join(h.seedDir, "rules.yaml"),
		"-tls-ca-file", filepath.Join(h.seedDir, "ca.crt"))
}

func (h *cliHarness) startTLSServer(t *testing.T, flags ...string) {
	t.Helper()

	server := h.start(t, nil, nil, h.serveArgs(t, flags...)...)
	h.waitForServer(t, server)
}

func (h *cliHarness) startTokenServer(t *testing.T, configFile string) {
	t.Helper()

	h.startTLSServer(t,
		"-config", configFile,
		"-tls-require-client-cert=false")
}

func (h *cliHarness) serveArgs(t *testing.T, flags ...string) []string {
	t.Helper()

	if _, err := os.Stat(h.seedDir); err != nil {
		h.seed(t)
	}

	args := []string{
		"serve",
		"-bind", "127.0.0.1:0",
		"-tls-cert-file", filepath.Join(h.seedDir, "tls.crt"),
		"-tls-key-file", filepath.Join(h.seedDir, "tls.key"),
	}

	return append(args, flags...)
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

func (h *cliHarness) clientArgsNoCert(args ...string) []string {
	prefix := []string{
		"-log-level", "error",
		"-server", h.server,
		"-tls-ca-file", filepath.Join(h.seedDir, "ca.crt"),
	}

	return append(prefix, args...)
}

func (h *cliHarness) clientTLSConfig(t *testing.T, clientCert bool) *tls.Config {
	t.Helper()

	files := cmd.TLSFiles{
		CAFiles: []string{filepath.Join(h.seedDir, "ca.crt")},
	}

	if clientCert {
		files.CertFile = filepath.Join(h.seedDir, "tls.crt")
		files.KeyFile = filepath.Join(h.seedDir, "tls.key")
	}

	tcfg, _, err := files.ClientConfig()
	if err != nil {
		t.Fatal(err)
	}

	return tcfg
}

func (h *cliHarness) getRootStatus(t *testing.T, tcfg *tls.Config) (int, error) {
	t.Helper()

	transport := &http.Transport{
		TLSClientConfig: tcfg,
	}
	defer transport.CloseIdleConnections()

	client := &http.Client{
		Transport: transport,
		Timeout:   cliTestTimeout,
	}

	res, err := client.Get("https://" + h.server + "/")
	if err != nil {
		return 0, err
	}
	defer res.Body.Close()

	return res.StatusCode, nil
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

func waitForHandlerReady(t *testing.T, handle *cliProcess, post func() cliResult) cliResult {
	t.Helper()

	var result cliResult
	deadline := time.After(cliTestTimeout)
	for {
		select {
		case <-deadline:
			t.Fatalf("timed out waiting for handler readiness; last post stderr:\n%s\nhandler stderr:\n%s",
				result.stderr, handle.stderr())
		default:
		}

		result = post()
		if result.err == nil {
			return result
		}
		if !bytes.Contains(result.stderr, []byte("no handler for post")) {
			result.mustSucceed(t)
		}
		time.Sleep(20 * time.Millisecond)
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
