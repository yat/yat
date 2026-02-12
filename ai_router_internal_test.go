package yat

import "testing"

func TestRouter_internalNoopBranches(t *testing.T) {
	t.Run("update with nil old and new is a no-op", func(t *testing.T) {
		rr := NewRouter()
		rr.update(nil, nil)
	})

	t.Run("match on zero path returns no entries", func(t *testing.T) {
		var tree rnode
		if got := tree.Match(Path{}); len(got) != 0 {
			t.Fatalf("len(entries): %d != 0", len(got))
		}
	})

	t.Run("leaf lookup without createMissing returns nil", func(t *testing.T) {
		var tree rnode
		if got := tree.leaf(NewPath("a/b"), false); got != nil {
			t.Fatal("expected nil")
		}
	})
}
