package proxy

import "testing"

func TestNewSeedsCommonFields(t *testing.T) {
	p := New("ss", "node", "1.2.3.4", 8388)
	if p.Name != "node" || p.Type != "ss" || p.Server != "1.2.3.4" || p.Port != 8388 {
		t.Fatalf("promoted fields wrong: %+v", p)
	}
	for k, want := range map[string]any{"name": "node", "type": "ss", "server": "1.2.3.4", "port": 8388} {
		if p.Clash[k] != want {
			t.Errorf("Clash[%q] = %v, want %v", k, p.Clash[k], want)
		}
	}
}

func TestSetSkipsEmptyAndNil(t *testing.T) {
	p := New("ss", "n", "h", 1)
	p.Set("password", "")  // empty string skipped
	p.Set("plugin", nil)   // nil skipped
	p.Set("cipher", "aes") // kept
	if _, ok := p.Clash["password"]; ok {
		t.Error("empty string should be skipped")
	}
	if _, ok := p.Clash["plugin"]; ok {
		t.Error("nil should be skipped")
	}
	if p.Clash["cipher"] != "aes" {
		t.Error("non-empty value should be set")
	}
}

func TestSetRawKeepsZeroValues(t *testing.T) {
	p := New("vmess", "n", "h", 1)
	p.SetRaw("alterId", 0)
	if v, ok := p.Clash["alterId"]; !ok || v != 0 {
		t.Errorf("SetRaw should keep zero value, got %v ok=%v", v, ok)
	}
}

func TestRenameUpdatesBoth(t *testing.T) {
	p := New("ss", "old", "h", 1)
	p.Rename("new")
	if p.Name != "new" || p.Clash["name"] != "new" {
		t.Errorf("Rename out of sync: name=%q clash=%v", p.Name, p.Clash["name"])
	}
}
