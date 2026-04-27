//go:build !human

package interpol_test

import (
	"testing"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"yat.io/yat/internal/interpol"
)

func TestCompileNoInterpolation(t *testing.T) {
	env := env(t)

	prog, err := interpol.Compile(env, "plain/path")
	if err != nil {
		t.Fatal(err)
	}
	if prog != nil {
		t.Fatal("expected nil program")
	}
}

func TestCompileSingleInterpolation(t *testing.T) {
	env := env(t, cel.Variable("i", cel.IntType))

	prog, err := interpol.Compile(env, "${i}")
	if err != nil {
		t.Fatal(err)
	}

	got := eval(t, prog, map[string]any{"i": int64(42)})
	if got != "42" {
		t.Fatalf("Eval() = %q, want %q", got, "42")
	}
}

func TestCompileMixedInterpolation(t *testing.T) {
	env := env(t,
		cel.Variable("s", cel.StringType),
		cel.Variable("i", cel.IntType),
	)

	prog, err := interpol.Compile(env, "a${s}b${i}")
	if err != nil {
		t.Fatal(err)
	}

	got := eval(t, prog, map[string]any{
		"s": "x",
		"i": int64(3),
	})
	if got != "axb3" {
		t.Fatalf("Eval() = %q, want %q", got, "axb3")
	}
}

func TestCompileWrapsInterpolationsWithInterpol(t *testing.T) {
	env := env(t,
		cel.Variable("s", cel.StringType),
		cel.Variable("i", cel.IntType),
		cel.Function("interpol",
			cel.Overload("test_interpol_string", []*cel.Type{cel.StringType}, cel.StringType,
				cel.UnaryBinding(func(arg ref.Val) ref.Val {
					return types.String("<" + string(arg.(types.String)) + ">")
				}),
			),
		),
	)

	prog, err := interpol.Compile(env, "a${s}b${i}")
	if err != nil {
		t.Fatal(err)
	}

	got := eval(t, prog, map[string]any{
		"s": "x",
		"i": int64(3),
	})
	if got != "a<x>b<3>" {
		t.Fatalf("Eval() = %q, want %q", got, "a<x>b<3>")
	}
}

func TestCompileNestedBraces(t *testing.T) {
	env := env(t)

	prog, err := interpol.Compile(env, `${{'a': {'b': 1}}['a']['b']}`)
	if err != nil {
		t.Fatal(err)
	}

	got := eval(t, prog, nil)
	if got != "1" {
		t.Fatalf("Eval() = %q, want %q", got, "1")
	}
}

func TestCompileBraceInsideLiteralsAndComments(t *testing.T) {
	env := env(t)

	cases := []struct {
		name string
		expr string
		want string
	}{
		{name: "string", expr: `${size("}")}`, want: "1"},
		{name: "raw_string", expr: `${size(r"}")}`, want: "1"},
		{name: "bytes", expr: `${size(b"}")}`, want: "1"},
		{name: "comment", expr: "${1 // }\n}", want: "1"},
		{name: "unicode_before_close", expr: `${size("é}")}`, want: "2"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			prog, err := interpol.Compile(env, tc.expr)
			if err != nil {
				t.Fatal(err)
			}

			got := eval(t, prog, nil)
			if got != tc.want {
				t.Fatalf("Eval() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestCompileUnterminatedInterpolation(t *testing.T) {
	env := env(t, cel.Variable("i", cel.IntType))

	_, err := interpol.Compile(env, "x\n${i")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestCompileBadInterpolationLocation(t *testing.T) {
	env := env(t)

	_, err := interpol.Compile(env, "x\n${1 + }")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestCompileEmptyInterpolation(t *testing.T) {
	env := env(t)

	_, err := interpol.Compile(env, `${}`)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestCompileNonStringableInterpolation(t *testing.T) {
	ce := env(t, cel.Variable("xs", cel.ListType(cel.StringType)))

	if _, err := interpol.Compile(ce, `${xs}`); err == nil {
		t.Fatal("no error")
	}
}

func TestReplaceNoInterpolation(t *testing.T) {
	env := env(t)

	got, err := interpol.Replace(env, "plain/path", "eg")
	if err != nil {
		t.Fatal(err)
	}
	if got != "plain/path" {
		t.Fatalf("Replace() = %q, want %q", got, "plain/path")
	}
}

func TestReplaceInterpolations(t *testing.T) {
	env := env(t,
		cel.Variable("s", cel.StringType),
		cel.Variable("i", cel.IntType),
	)

	got, err := interpol.Replace(env, "a${s}b${i}", "eg")
	if err != nil {
		t.Fatal(err)
	}
	if got != "aegbeg" {
		t.Fatalf("Replace() = %q, want %q", got, "aegbeg")
	}
}

func TestReplaceIgnoresInterpolFunction(t *testing.T) {
	env := env(t,
		cel.Function("interpol",
			cel.Overload("test_interpol_string", []*cel.Type{cel.StringType}, cel.StringType,
				cel.UnaryBinding(func(arg ref.Val) ref.Val {
					return types.String("<" + string(arg.(types.String)) + ">")
				}),
			),
		),
	)

	got, err := interpol.Replace(env, "a${'x'}b", "eg")
	if err != nil {
		t.Fatal(err)
	}
	if got != "aegb" {
		t.Fatalf("Replace() = %q, want %q", got, "aegb")
	}
}

func TestReplaceBadInterpolation(t *testing.T) {
	env := env(t)

	_, err := interpol.Replace(env, "x\n${1 + }", "eg")
	if err == nil {
		t.Fatal("expected error")
	}
}

func env(t testing.TB, opts ...cel.EnvOption) *cel.Env {
	t.Helper()

	env, err := cel.NewEnv(opts...)
	if err != nil {
		t.Fatal(err)
	}
	return env
}

func eval(t testing.TB, prog cel.Program, vars map[string]any) string {
	t.Helper()

	val, _, err := prog.Eval(vars)
	if err != nil {
		t.Fatal(err)
	}

	s, ok := val.Value().(string)
	if !ok {
		t.Fatalf("result is %T, not string", val.Value())
	}

	return s
}
