package yat_test

import (
	"encoding/json"
	"strconv"
	"testing"

	"github.com/google/go-cmp/cmp"
	"yat.io/yat"
)

// FIX: stub
func TestRuleSet_Compile(t *testing.T) {
	rs := yat.RuleSet{
		Rules: []yat.Rule{
			{
				Grants: []yat.Grant{
					// doesn't apply because the rule doesn't have Claims
					{Topic: yat.Topic("**"), Action: yat.PUB},
				},
			},

			{
				Claims: map[string]string{
					"sub": "never",
				},

				Grants: []yat.Grant{
					// doesn't apply because the claims never match
					{Topic: yat.Topic("**"), Action: yat.PUB},
				},
			},

			{
				Claims: map[string]string{
					"sub": "test",
				},

				Grants: []yat.Grant{
					{Topic: yat.Topic("**"), Action: yat.SUB},
					{Topic: yat.Topic("test/**"), Action: yat.PUB},
				},
			},
		},
	}

	allow := rs.Compile(map[string]any{
		"sub": "test",
	},
	)

	tcs := []struct {
		Topic  string
		Action yat.Action
		Allow  bool
	}{
		{"x", yat.SUB, true},
		{"x", yat.PUB, false},
		{"test/x", yat.PUB | yat.SUB, true},
	}

	for i, tc := range tcs {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			if allow(yat.Topic(tc.Topic), tc.Action) != tc.Allow {
				t.Errorf("allow(%s, %v) != %v", tc.Topic, tc.Action, tc.Allow)
			}
		})
	}
}

func TestActionJSON(t *testing.T) {
	tcs := []struct {
		Action yat.Action
		Array  []string
	}{
		{yat.PUB, []string{"pub"}},
		{yat.SUB, []string{"sub"}},
		{yat.PUB | yat.SUB, []string{"pub", "sub"}},
		{yat.PUB | yat.SUB | 1<<15, []string{"pub", "sub"}},
	}

	for i, tc := range tcs {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			data, err := json.Marshal(tc.Action)
			if err != nil {
				t.Fatal(err)
			}

			var gotArray []string
			if err := json.Unmarshal(data, &gotArray); err != nil {
				t.Fatal(err)
			}

			if diff := cmp.Diff(tc.Array, gotArray); diff != "" {
				t.Error(diff)
			}

			var got yat.Action
			if err := json.Unmarshal(data, &got); err != nil {
				t.Fatal(err)
			}

			if got != tc.Action&(yat.PUB|yat.SUB) {
				t.Errorf("roundtrip: %#x != %#x", got, tc.Action)
			}
		})
	}
}

func TestAction_String(t *testing.T) {
	tcs := []struct {
		Action yat.Action
		String string
	}{
		{yat.PUB, "PUB"},
		{yat.SUB, "SUB"},
		{yat.PUB | yat.SUB, "PUB|SUB"},
		{yat.PUB | yat.SUB | 1<<15, "PUB|SUB|0x8000"},
	}

	for i, tc := range tcs {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			if got, want := tc.Action.String(), tc.String; got != want {
				t.Errorf("%q != %q", got, want)
			}
		})
	}
}

func TestAction_UnmarshalJSON(t *testing.T) {
	tcs := []string{
		`[`,
		`1`,
		`"pub"`,
		`["pub", "del"]`,
	}

	for i, tc := range tcs {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			var a yat.Action
			err := json.Unmarshal([]byte(tc), &a)
			if err == nil {
				t.Error("no error")
			}
		})
	}
}
