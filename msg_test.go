package yat_test

import (
	"fmt"
	"testing"
	"time"

	"yat.io/yat"
)

func TestMsg_IsExpired(t *testing.T) {
	tcs := []struct {
		Msg     yat.Msg
		Expired bool
	}{
		{yat.Msg{}, false},
		{yat.Msg{Deadline: time.Now().Add(1 * time.Second)}, false},
		{yat.Msg{Deadline: time.Now().Add(-1 * time.Second)}, true},
	}

	for i, tc := range tcs {
		t.Run(fmt.Sprintf("tc[%d]", i), func(t *testing.T) {
			if tc.Msg.IsExpired() != tc.Expired {
				t.Errorf("IsExpired != %v", tc.Expired)
			}
		})
	}
}
