package cli

import (
	"bytes"
	"testing"
)

func TestEscapeFilter(t *testing.T) {
	cases := []struct {
		in   []string
		out  string
		quit bool
	}{
		{[]string{"ls\r"}, "ls\r", false},
		{[]string{"\x03"}, "\x03", false},
		{[]string{"~."}, "", true},
		{[]string{"a\r~."}, "a\r", true},
		{[]string{"a~."}, "a~.", false},
		{[]string{"~~"}, "~", false},
		{[]string{"~x"}, "~x", false},
		{[]string{"\r~", "."}, "\r", true},
		{[]string{"vim\r", "~"}, "vim\r", false},
	}
	for _, c := range cases {
		e := &escape{atLineStart: true}
		var got []byte
		quit := false
		for _, chunk := range c.in {
			out, q := e.filter([]byte(chunk))
			got = append(got, out...)
			quit = quit || q
		}
		if !bytes.Equal(got, []byte(c.out)) || quit != c.quit {
			t.Errorf("%q: got %q quit=%v, want %q quit=%v", c.in, got, quit, c.out, c.quit)
		}
	}
}

func TestFilterHosts(t *testing.T) {
	hosts := []Host{{Alias: "home", Name: "Home NAS", Endpoint: "10.0.0.2:22", Username: "me"}, {Alias: "vps", Name: "Cloud", Endpoint: "vps.example:22", Username: "root"}}
	if got := Filter(hosts, "NAS"); len(got) != 1 || got[0].Alias != "home" {
		t.Fatalf("filter by name: %v", got)
	}
	if got := Filter(hosts, "root@"); len(got) != 1 || got[0].Alias != "vps" {
		t.Fatalf("filter by user: %v", got)
	}
	if got := Filter(hosts, ""); len(got) != 2 {
		t.Fatalf("empty filter: %v", got)
	}
}

func TestSelectHost(t *testing.T) {
	hosts := []Host{{Alias: "home"}, {Alias: "homelab"}, {Alias: "vps"}}
	var out bytes.Buffer
	h, err := selectHost(bytes.NewBufferString("lab\n\n"), &out, hosts)
	if err != nil || h.Alias != "homelab" {
		t.Fatalf("filter then enter: %v %v", h, err)
	}
	h, err = selectHost(bytes.NewBufferString("3\n"), &out, hosts)
	if err != nil || h.Alias != "vps" {
		t.Fatalf("by number: %v %v", h, err)
	}
	if _, err := selectHost(bytes.NewBufferString("q\n"), &out, hosts); err == nil {
		t.Fatal("quit selected a host")
	}
}
