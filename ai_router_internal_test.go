package yat

import (
	"errors"
	"testing"
)

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

func TestRouter_Publish_reservedInbox(t *testing.T) {
	rr := NewRouter()
	msgC := make(chan Msg, 1)
	unsub, err := rr.Subscribe(Sel{Path: NewPath("chat/room")}, func(m Msg) {
		msgC <- m
	})
	if err != nil {
		t.Fatal(err)
	}
	defer unsub()

	err = rr.Publish(Msg{
		Path:  NewPath("chat/room"),
		Inbox: NewPath("$svr/events/stop"),
	})
	if !errors.Is(err, errReservedInbox) {
		t.Fatalf("error: %v", err)
	}

	select {
	case got := <-msgC:
		t.Fatalf("unexpected message: path=%q data=%q inbox=%q", got.Path.String(), got.Data, got.Inbox.String())
	default:
	}
}
