package parser

import "testing"

func TestSplitHostPort(t *testing.T) {
	cases := []struct {
		in   string
		host string
		port int
	}{
		{"1.2.3.4:443", "1.2.3.4", 443},
		{"example.com:8080", "example.com", 8080},
		{"[2001:db8::1]:443", "2001:db8::1", 443},
		{"[fe80::1]", "fe80::1", 0},
		{"hostonly", "hostonly", 0},
	}
	for _, c := range cases {
		h, p := splitHostPort(c.in)
		if h != c.host || p != c.port {
			t.Errorf("splitHostPort(%q) = %q,%d want %q,%d", c.in, h, p, c.host, c.port)
		}
	}
}

func TestAnyToInt(t *testing.T) {
	if anyToInt(float64(443)) != 443 {
		t.Error("float64")
	}
	if anyToInt(8080) != 8080 {
		t.Error("int")
	}
	if anyToInt("1234") != 1234 {
		t.Error("string")
	}
	if anyToInt(nil) != 0 || anyToInt([]int{}) != 0 {
		t.Error("unknown -> 0")
	}
}

func TestBoolish(t *testing.T) {
	for _, s := range []string{"1", "true", "YES", "on"} {
		if !boolish(s) {
			t.Errorf("boolish(%q) should be true", s)
		}
	}
	if boolish("0") || boolish("") {
		t.Error("falsey values")
	}
}

func TestB64Decode(t *testing.T) {
	if out, ok := b64decode("aGVsbG8="); !ok || out != "hello" {
		t.Errorf("std b64 = %q,%v", out, ok)
	}
	// Not base64 -> returns input, ok=false.
	if out, ok := b64decode("!!!not-b64!!!"); ok || out != "!!!not-b64!!!" {
		t.Errorf("non-b64 should pass through: %q,%v", out, ok)
	}
}
