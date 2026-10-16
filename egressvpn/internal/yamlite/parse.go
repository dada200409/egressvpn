// Package yamlite parses the subset of YAML this project's config file needs:
// nested maps, block sequences, and scalar values.
//
// It is deliberately not a YAML implementation. The config it reads turns into
// firewall rules and routing, so the failure mode that matters is "silently
// parsed something different from what the operator meant". Anything outside the
// subset - flow mappings, anchors, folded scalars, tabs - is a hard error rather
// than a guess, and so are unknown keys and duplicate keys.
package yamlite

import (
	"fmt"
	"strings"
)

type Kind int

const (
	Scalar Kind = iota
	Mapping
	Sequence
)

type Node struct {
	Kind  Kind
	Str   string // scalar text, quotes removed
	Keys  []string
	Vals  map[string]*Node
	Items []*Node
	Line  int
}

func (n *Node) set(key string, val *Node) error {
	if _, dup := n.Vals[key]; dup {
		return fmt.Errorf("line %d: duplicate key %q", val.Line, key)
	}
	n.Keys = append(n.Keys, key)
	if n.Vals == nil {
		n.Vals = map[string]*Node{}
	}
	n.Vals[key] = val
	return nil
}

type line struct {
	indent int
	text   string
	num    int
}

type parser struct {
	lines []line
	i     int
}

// Parse builds the node tree for a single-document config.
func Parse(data []byte) (*Node, error) {
	lines, err := scan(string(data))
	if err != nil {
		return nil, err
	}
	if len(lines) == 1 && lines[0].text == "---" {
		lines = lines[1:]
	}
	if len(lines) == 0 {
		return nil, fmt.Errorf("empty config")
	}
	p := &parser{lines: lines}
	root, err := p.parse(lines[0].indent)
	if err != nil {
		return nil, err
	}
	if p.i < len(p.lines) {
		return nil, fmt.Errorf("line %d: unexpected indentation", p.lines[p.i].num)
	}
	return root, nil
}

func scan(s string) ([]line, error) {
	var out []line
	for i, raw := range strings.Split(s, "\n") {
		num := i + 1
		body, err := stripComment(raw, num)
		if err != nil {
			return nil, err
		}
		if strings.TrimSpace(body) == "" {
			continue
		}
		indent := 0
		for indent < len(body) && body[indent] == ' ' {
			indent++
		}
		if indent < len(body) && body[indent] == '\t' {
			return nil, fmt.Errorf("line %d: tab used for indentation; YAML wants spaces", num)
		}
		if strings.HasSuffix(body, "\r") {
			body = strings.TrimSuffix(body, "\r")
		}
		text := strings.TrimRight(body[indent:], " ")
		if text == "..." {
			return nil, fmt.Errorf("line %d: multi-document files are not supported", num)
		}
		out = append(out, line{indent: indent, text: text, num: num})
	}
	return out, nil
}

// stripComment removes a trailing comment, honouring quotes so a password
// containing " #..." survives intact.
func stripComment(raw string, num int) (string, error) {
	var quote byte
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case c == '\'' || c == '"':
			quote = c
		case c == '#' && (i == 0 || raw[i-1] == ' ' || raw[i-1] == '\t'):
			return raw[:i], nil
		}
	}
	if quote != 0 {
		return "", fmt.Errorf("line %d: unterminated %c quote", num, quote)
	}
	return raw, nil
}

func (p *parser) parse(indent int) (*Node, error) {
	if p.i >= len(p.lines) {
		return nil, fmt.Errorf("line %d: expected a value, file ended", p.lines[len(p.lines)-1].num)
	}
	if strings.HasPrefix(p.lines[p.i].text, "- ") || p.lines[p.i].text == "-" {
		return p.parseSeq(indent)
	}
	return p.parseMap(indent)
}

func (p *parser) parseMap(indent int) (*Node, error) {
	n := &Node{Kind: Mapping, Line: p.lines[p.i].num}
	for p.i < len(p.lines) {
		l := p.lines[p.i]
		if l.indent < indent {
			break
		}
		if l.indent > indent {
			return nil, fmt.Errorf("line %d: unexpected indentation inside %q", l.num, keyOf(n))
		}
		if strings.HasPrefix(l.text, "- ") {
			break
		}
		key, rest, ok := splitKey(l.text)
		if !ok {
			return nil, fmt.Errorf("line %d: expected \"key: value\", got %q", l.num, l.text)
		}
		p.i++
		val, err := p.value(rest, l, indent)
		if err != nil {
			return nil, err
		}
		if err := n.set(key, val); err != nil {
			return nil, err
		}
	}
	return n, nil
}

// keyOf only labels errors; a mapping node keeps its first key for that.
func keyOf(n *Node) string {
	if len(n.Keys) > 0 {
		return n.Keys[0]
	}
	return "<map>"
}

func (p *parser) value(rest string, l line, indent int) (*Node, error) {
	if rest != "" {
		return scalar(rest, l.num)
	}
	// a block value: whatever follows, indented deeper than this key
	if p.i < len(p.lines) && p.lines[p.i].indent > indent {
		return p.parse(p.lines[p.i].indent)
	}
	return &Node{Kind: Scalar, Str: "", Line: l.num}, nil
}

func (p *parser) parseSeq(indent int) (*Node, error) {
	n := &Node{Kind: Sequence, Line: p.lines[p.i].num}
	for p.i < len(p.lines) {
		l := p.lines[p.i]
		if l.indent != indent || !(strings.HasPrefix(l.text, "- ") || l.text == "-") {
			break
		}
		if l.text == "-" {
			p.i++
			if p.i >= len(p.lines) || p.lines[p.i].indent <= indent {
				return nil, fmt.Errorf("line %d: list item has no value", l.num)
			}
			item, err := p.parse(p.lines[p.i].indent)
			if err != nil {
				return nil, err
			}
			n.Items = append(n.Items, item)
			continue
		}
		raw := l.text[1:]
		if raw[0] != ' ' {
			return nil, fmt.Errorf("line %d: expected a space after \"-\"", l.num)
		}
		col := l.indent + 1 + len(raw) - len(strings.TrimLeft(raw, " "))
		rest := strings.TrimSpace(raw)
		if _, _, ok := splitKey(rest); ok {
			// "- name: alice" opens a mapping whose later keys sit at column col
			p.lines[p.i] = line{indent: col, text: rest, num: l.num}
			item, err := p.parseMap(col)
			if err != nil {
				return nil, err
			}
			n.Items = append(n.Items, item)
			continue
		}
		item, err := scalar(rest, l.num)
		if err != nil {
			return nil, err
		}
		n.Items = append(n.Items, item)
		p.i++
	}
	return n, nil
}

// splitKey finds the ": " that separates a key from its value. An unquoted value
// may itself contain ":" as long as no space follows, so endpoints such as
// 203.0.113.20:51820 stay intact.
func splitKey(text string) (key, rest string, ok bool) {
	var quote byte
	for i := 0; i < len(text); i++ {
		c := text[i]
		if quote != 0 {
			if c == quote {
				quote = 0
			}
			continue
		}
		if c == '\'' || c == '"' {
			quote = c
			continue
		}
		if c != ':' {
			continue
		}
		if i+1 == len(text) || text[i+1] == ' ' {
			return strings.TrimSpace(text[:i]), strings.TrimSpace(text[i+1:]), true
		}
	}
	return "", "", false
}

func scalar(s string, num int) (*Node, error) {
	if s == "" {
		return &Node{Kind: Scalar, Line: num}, nil
	}
	switch s[0] {
	case '{', '[', '&', '*', '!', '|', '>', '%', '@', '`':
		return nil, fmt.Errorf("line %d: %q is outside the supported YAML subset", num, s)
	}
	if len(s) >= 2 && (s[0] == '"' || s[0] == '\'') && s[len(s)-1] == s[0] {
		inner := s[1 : len(s)-1]
		if s[0] == '\'' {
			return &Node{Kind: Scalar, Str: strings.ReplaceAll(inner, "''", "'"), Line: num}, nil
		}
		return &Node{Kind: Scalar, Str: unescapeDouble(inner), Line: num}, nil
	}
	if strings.ContainsAny(s, "'\"") {
		return nil, fmt.Errorf("line %d: unbalanced quote in %q", num, s)
	}
	return &Node{Kind: Scalar, Str: s, Line: num}, nil
}

func unescapeDouble(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+1 >= len(s) {
			b.WriteByte(s[i])
			continue
		}
		i++
		switch s[i] {
		case 'n':
			b.WriteByte('\n')
		case 't':
			b.WriteByte('\t')
		case '\\':
			b.WriteByte('\\')
		case '"':
			b.WriteByte('"')
		default:
			b.WriteByte('\\')
			b.WriteByte(s[i])
		}
	}
	return b.String()
}
