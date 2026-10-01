package pep

import (
	"strings"
	"testing"
)

func TestQuorumResilienceNotice(t *testing.T) {
	for _, c := range []struct {
		k, n int
		want string // "" = silence
	}{
		{1, 1, "k=1"},
		{1, 3, "k=1"},
		{2, 2, "sans clé de rechange"},
		{3, 3, "sans clé de rechange"},
		{2, 3, ""},
		{3, 5, ""},
	} {
		got := QuorumResilienceNotice("pepd", c.k, c.n)
		if c.want == "" && got != "" || c.want != "" && !strings.Contains(got, c.want) {
			t.Errorf("k=%d n=%d : %q, attendu %q", c.k, c.n, got, c.want)
		}
	}
}
