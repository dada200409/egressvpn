package yamlite

import (
	"strings"
	"testing"
)

type inner struct {
	Name  string `yaml:"name"`
	Pool  string `yaml:"pool"`
	Ports []int  `yaml:"ports"`
}

type doc struct {
	Host     string   `yaml:"host"`
	Endpoint string   `yaml:"endpoint"`
	Mtu      int      `yaml:"mtu"`
	Embed    bool     `yaml:"embed"`
	Prefill  *bool    `yaml:"prefill"`
	DNS      []string `yaml:"dns"`
	Faces    []inner  `yaml:"faces"`
	Note     string   `yaml:"note"`
}

func load(t *testing.T, body string) *doc {
	t.Helper()
	var d doc
	if err := Unmarshal([]byte(body), &d); err != nil {
		t.Fatalf("rejected valid input: %v", err)
	}
	return &d
}

func TestDecodesShapes(t *testing.T) {
	d := load(t, `host: vpn.example.com
endpoint: 203.0.113.20:51820 # a trailing comment
mtu: 1380
embed: true
prefill: false
dns:
  - 1.1.1.1
  - 8.8.8.8
faces:
  - name: local
    pool: 10.90.1.0/24
    ports:
      - 500
      - 4500
  - name: via-b
    pool: 10.90.2.0/24
note: 'has # inside quotes'
`)
	if d.Host != "vpn.example.com" || d.Mtu != 1380 || !d.Embed {
		t.Fatalf("scalars wrong: %+v", d)
	}
	// an unquoted value may contain ":" when no space follows, so a host:port stays whole
	if d.Endpoint != "203.0.113.20:51820" {
		t.Errorf("endpoint mangled: %q", d.Endpoint)
	}
	if d.Note != "has # inside quotes" {
		t.Errorf("comment stripped inside quotes: %q", d.Note)
	}
	if d.Prefill == nil || *d.Prefill {
		t.Errorf("prefill: want explicit false, got %+v", d.Prefill)
	}
	if strings.Join(d.DNS, ",") != "1.1.1.1,8.8.8.8" {
		t.Errorf("dns list wrong: %v", d.DNS)
	}
	if len(d.Faces) != 2 || d.Faces[0].Name != "local" || d.Faces[1].Pool != "10.90.2.0/24" {
		t.Fatalf("list of maps wrong: %+v", d.Faces)
	}
	if len(d.Faces[0].Ports) != 2 || d.Faces[0].Ports[1] != 4500 {
		t.Errorf("nested list wrong: %v", d.Faces[0].Ports)
	}
}

func TestAbsentKeyLeavesZero(t *testing.T) {
	// applyDefaults relies on this: unset must differ from set-to-false
	d := load(t, "host: x\n")
	if d.Prefill != nil {
		t.Errorf("prefill should stay nil, got %v", *d.Prefill)
	}
	if d.Mtu != 0 || d.Embed {
		t.Error("unset scalars should stay zero")
	}
}

func TestRejects(t *testing.T) {
	cases := map[string]string{
		"unknown key":        "hosts: x\n",
		"duplicate key":      "host: a\nhost: b\n",
		"tab indent":         "host: a\n\tsub: b\n",
		"flow mapping":       "face: {name: local}\n",
		"flow sequence":      "dns: [1.1.1.1]\n",
		"anchor":             "base: &x\n",
		"alias":              "copy: *x\n",
		"folded scalar":      "note: >\n  text\n",
		"YAML 1.1 bool":      "embed: yes\n",
		"non-numeric int":    "mtu: 1380ish\n",
		"list where map":     "- host: a\n",
		"bad indentation":    "host: a\n  extra: b\n",
		"unterminated quote": `host: "abc` + "\n",
	}
	for name, body := range cases {
		var d doc
		err := Unmarshal([]byte(body), &d)
		if err == nil {
			t.Errorf("%s: accepted %q, and a silently wrong config here becomes wrong firewall rules", name, body)
			continue
		}
		if !strings.Contains(err.Error(), "line") {
			t.Errorf("%s: error should name a line, got %v", name, err)
		}
	}
}

func TestUnknownKeyNamesPath(t *testing.T) {
	var d doc
	err := Unmarshal([]byte("faces:\n  - name: a\n    pol: 10.0.0.0/24\n"), &d)
	if err == nil || !strings.Contains(err.Error(), "faces[0].pol") {
		t.Errorf("want the offending path in the message, got %v", err)
	}
}

func TestBlockValueFollowsParent(t *testing.T) {
	d := load(t, `host: a
faces:
  - name: x
    pool: 10.0.0.0/24
mtu: 1400
`)
	if len(d.Faces) != 1 || d.Faces[0].Pool != "10.0.0.0/24" || d.Mtu != 1400 {
		t.Errorf("sibling key after a list got swallowed: %+v", d)
	}
}
