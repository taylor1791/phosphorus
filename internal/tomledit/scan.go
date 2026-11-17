package tomledit

import (
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

// The scanner finds the byte spans of keys, values and array elements in a
// document that the real parser has already accepted, so it can assume the
// input is valid TOML and only has to classify it correctly.

// node is one value in the document.
type node struct {
	path       []string
	kind       byte // 'a' array, 't' inline table, 's' single-line string, 'o' anything else
	start, end int  // the value's span
	// lineKV: a key/value statement on its own in a table section (not
	// inside an inline table). keyStart is where its key begins.
	lineKV   bool
	keyStart int
	elems    []elem // arrays only
}

// elem is one array element.
type elem struct {
	start, end int
	str        string
	isStr      bool // a single-line string, decoded into str
}

// section is a [table] header and the statements under it. The root
// section has header == -1.
type section struct {
	path      []string
	array     bool // [[array of tables]]
	header    int  // offset of '[' or -1 for the root
	headerEnd int  // offset just past the header line (or 0 for the root)
	lastEnd   int  // offset just past the line of the last statement, or -1
}

type index struct {
	nodes    map[string]*node
	sections []*section
}

func pathKey(p []string) string { return strings.Join(p, "\x00") }

type scanner struct {
	src []byte
	pos int
	idx *index
	// inArrayTable is set while statements belong to a [[...]] section;
	// their values are not indexed because their paths are ambiguous.
	inArrayTable bool
}

func scan(src []byte) (ix *index, err error) {
	defer func() {
		if r := recover(); r != nil {
			if se, ok := r.(scanError); ok {
				ix, err = nil, se
				return
			}
			panic(r)
		}
	}()
	s := &scanner{src: src, idx: &index{nodes: map[string]*node{}}}
	root := &section{header: -1, lastEnd: -1}
	s.idx.sections = append(s.idx.sections, root)
	cur := root
	for {
		s.skipBlank(true)
		if s.pos >= len(src) {
			break
		}
		if src[s.pos] == '[' {
			sec := &section{header: s.pos, lastEnd: -1}
			s.pos++
			if s.peek() == '[' {
				sec.array = true
				s.pos++
			}
			s.skipSpace()
			sec.path = s.key()
			s.skipSpace()
			s.expect(']')
			if sec.array {
				s.expect(']')
			}
			s.restOfLine()
			sec.headerEnd = s.pos
			s.idx.sections = append(s.idx.sections, sec)
			cur = sec
			s.inArrayTable = sec.array
			continue
		}
		keyStart := s.pos
		k := s.key()
		s.skipSpace()
		s.expect('=')
		s.skipSpace()
		full := append(append([]string{}, cur.path...), k...)
		n := s.value(full, !s.inArrayTable)
		n.lineKV, n.keyStart = true, keyStart
		s.restOfLine()
		cur.lastEnd = s.pos
	}
	return s.idx, nil
}

type scanError string

func (e scanError) Error() string { return string(e) }

func (s *scanner) fail(format string, a ...any) {
	panic(scanError(fmt.Sprintf("offset %d: ", s.pos) + fmt.Sprintf(format, a...)))
}

func (s *scanner) peek() byte {
	if s.pos < len(s.src) {
		return s.src[s.pos]
	}
	return 0
}

func (s *scanner) expect(c byte) {
	if s.peek() != c {
		s.fail("expected %q", c)
	}
	s.pos++
}

func (s *scanner) skipSpace() {
	for s.pos < len(s.src) && (s.src[s.pos] == ' ' || s.src[s.pos] == '\t') {
		s.pos++
	}
}

// skipBlank skips spaces, comments and (if newlines) line breaks.
func (s *scanner) skipBlank(newlines bool) {
	for s.pos < len(s.src) {
		switch c := s.src[s.pos]; {
		case c == ' ' || c == '\t':
			s.pos++
		case c == '#':
			for s.pos < len(s.src) && s.src[s.pos] != '\n' {
				s.pos++
			}
		case (c == '\n' || c == '\r') && newlines:
			s.pos++
		default:
			return
		}
	}
}

// restOfLine skips trailing space and a comment, and the line break.
func (s *scanner) restOfLine() {
	s.skipBlank(false)
	if s.peek() == '\r' {
		s.pos++
	}
	if s.peek() == '\n' {
		s.pos++
	}
}

func isBare(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-'
}

// key reads a dotted key.
func (s *scanner) key() []string {
	var parts []string
	for {
		s.skipSpace()
		switch s.peek() {
		case '"':
			start := s.pos
			s.basicString()
			v, ok := decodeBasic(string(s.src[start+1 : s.pos-1]))
			if !ok {
				s.fail("cannot decode quoted key")
			}
			parts = append(parts, v)
		case '\'':
			start := s.pos
			s.literalString()
			parts = append(parts, string(s.src[start+1:s.pos-1]))
		default:
			start := s.pos
			for s.pos < len(s.src) && isBare(s.src[s.pos]) {
				s.pos++
			}
			if s.pos == start {
				s.fail("expected a key")
			}
			parts = append(parts, string(s.src[start:s.pos]))
		}
		s.skipSpace()
		if s.peek() != '.' {
			return parts
		}
		s.pos++
	}
}

func (s *scanner) basicString() {
	s.expect('"')
	for s.pos < len(s.src) {
		switch s.src[s.pos] {
		case '\\':
			s.pos += 2
		case '"':
			s.pos++
			return
		case '\n':
			s.fail("newline in string")
		default:
			s.pos++
		}
	}
	s.fail("unterminated string")
}

func (s *scanner) literalString() {
	s.expect('\'')
	for s.pos < len(s.src) {
		switch s.src[s.pos] {
		case '\'':
			s.pos++
			return
		case '\n':
			s.fail("newline in string")
		default:
			s.pos++
		}
	}
	s.fail("unterminated string")
}

func (s *scanner) hasPrefix(p string) bool { return strings.HasPrefix(string(s.src[s.pos:]), p) }

// multiline skips a """ or ”' string; q is the quote character.
func (s *scanner) multiline(q byte) {
	s.pos += 3
	for s.pos < len(s.src) {
		c := s.src[s.pos]
		if c == '\\' && q == '"' {
			s.pos += 2
			continue
		}
		if c == q && s.hasPrefix(strings.Repeat(string(q), 3)) {
			s.pos += 3
			// Up to two more quotes may belong to the content.
			for i := 0; i < 2 && s.peek() == q; i++ {
				s.pos++
			}
			return
		}
		s.pos++
	}
	s.fail("unterminated multi-line string")
}

// value reads a value at path. When record is set the value (and the
// values nested in inline tables) are added to the index.
func (s *scanner) value(path []string, record bool) *node {
	n := &node{path: path, start: s.pos, kind: 'o'}
	switch {
	case s.hasPrefix(`"""`):
		s.multiline('"')
	case s.hasPrefix(`'''`):
		s.multiline('\'')
	case s.peek() == '"':
		s.basicString()
		n.kind = 's'
	case s.peek() == '\'':
		s.literalString()
		n.kind = 's'
	case s.peek() == '[':
		n.kind = 'a'
		s.pos++
		for {
			s.skipBlank(true)
			if s.peek() == ']' {
				s.pos++
				break
			}
			e := s.value(nil, false)
			el := elem{start: e.start, end: e.end}
			if e.kind == 's' {
				el.str, el.isStr = decodeString(string(s.src[e.start:e.end]))
			}
			n.elems = append(n.elems, el)
			s.skipBlank(true)
			if s.peek() == ',' {
				s.pos++
				continue
			}
			s.skipBlank(true)
			s.expect(']')
			break
		}
	case s.peek() == '{':
		n.kind = 't'
		s.pos++
		for {
			s.skipBlank(true)
			if s.peek() == '}' {
				s.pos++
				break
			}
			k := s.key()
			s.skipSpace()
			s.expect('=')
			s.skipSpace()
			s.value(append(append([]string{}, path...), k...), record)
			s.skipBlank(true)
			if s.peek() == ',' {
				s.pos++
				continue
			}
			s.skipBlank(true)
			s.expect('}')
			break
		}
	default:
		for s.pos < len(s.src) {
			c := s.src[s.pos]
			if c == ',' || c == ']' || c == '}' || c == '#' || c == '\n' || c == '\r' {
				break
			}
			s.pos++
		}
		for s.pos > n.start && (s.src[s.pos-1] == ' ' || s.src[s.pos-1] == '\t') {
			s.pos--
		}
		if s.pos == n.start {
			s.fail("expected a value")
		}
	}
	n.end = s.pos
	if record && path != nil {
		s.idx.nodes[pathKey(path)] = n
	}
	return n
}

func decodeString(raw string) (string, bool) {
	if strings.HasPrefix(raw, "'") {
		return raw[1 : len(raw)-1], true
	}
	return decodeBasic(raw[1 : len(raw)-1])
}

// decodeBasic decodes the inside of a single-line basic string.
func decodeBasic(s string) (string, bool) {
	if !strings.Contains(s, `\`) {
		return s, true
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' {
			b.WriteByte(s[i])
			continue
		}
		i++
		if i >= len(s) {
			return "", false
		}
		switch s[i] {
		case 'b':
			b.WriteByte('\b')
		case 't':
			b.WriteByte('\t')
		case 'n':
			b.WriteByte('\n')
		case 'f':
			b.WriteByte('\f')
		case 'r':
			b.WriteByte('\r')
		case 'e':
			b.WriteByte(0x1b)
		case '"':
			b.WriteByte('"')
		case '\\':
			b.WriteByte('\\')
		case 'u', 'U', 'x':
			n := map[byte]int{'u': 4, 'U': 8, 'x': 2}[s[i]]
			if i+1+n > len(s) {
				return "", false
			}
			v, err := strconv.ParseUint(s[i+1:i+1+n], 16, 32)
			if err != nil || !utf8.ValidRune(rune(v)) {
				return "", false
			}
			b.WriteRune(rune(v))
			i += n
		default:
			return "", false
		}
	}
	return b.String(), true
}
