package cli

import (
	"regexp"
	"strings"
	"testing"
)

// nodeDotenvParse is a faithful port of Node dotenv's parse (lib/main.js,
// v16 and later):
//
//	LINE = /(?:^|^)\s*(?:export\s+)?([\w.-]+)(?:\s*=\s*?|:\s+?)(\s*'(?:\\'|[^'])*'|\s*"(?:\\"|[^"])*"|\s*`(?:\\`|[^`])*`|[^#\r\n]+)?\s*(?:#.*)?(?:$|$)/mg
//	lines = src.replace(/\r\n?/mg, '\n')
//	value = (match[2] || '').trim()
//	maybeQuote = value[0]
//	value = value.replace(/^(['"`])([\s\S]*)\1$/mg, '$2')
//	if maybeQuote === '"': value = value.replace(/\\n/g, '\n').replace(/\\r/g, '\r')
//
// The pattern uses only constructs RE2 shares with JavaScript; the
// backreference \1 in the unquoting step is done by hand.
var nodeLine = regexp.MustCompile("(?m)(?:^|^)\\s*(?:export\\s+)?([\\w.-]+)(?:\\s*=\\s*?|:\\s+?)(\\s*'(?:\\\\'|[^'])*'|\\s*\"(?:\\\\\"|[^\"])*\"|\\s*`(?:\\\\`|[^`])*`|[^#\\r\\n]+)?\\s*(?:#.*)?(?:$|$)")

func nodeDotenvParse(src string) map[string]string {
	src = regexp.MustCompile(`\r\n?`).ReplaceAllString(src, "\n")
	out := map[string]string{}
	for _, m := range nodeLine.FindAllStringSubmatch(src, -1) {
		v := strings.TrimSpace(m[2])
		q := byte(0)
		if v != "" {
			q = v[0]
		}
		if len(v) >= 2 && (q == '\'' || q == '"' || q == '`') && v[len(v)-1] == q {
			v = v[1 : len(v)-1]
		}
		if q == '"' {
			v = strings.ReplaceAll(v, `\n`, "\n")
			v = strings.ReplaceAll(v, `\r`, "\r")
		}
		out[m[1]] = v
	}
	return out
}

// pyDotenvParse ports python-dotenv's parser (parser.py) for the forms
// export writes, with interpolation off:
//
//	single quoted: '((?:\\'|[^'])*)'  then decode \\ and \'
//	double quoted: "((?:\\"|[^"])*)"  then decode \\ \' \" \a \b \f \n \r \t \v
//	unquoted:      ([^\r\n]*)          then drop a " #" comment and trailing space
var (
	pySingle    = regexp.MustCompile(`^'((?:\\'|[^'])*)'`)
	pyDouble    = regexp.MustCompile(`^"((?:\\"|[^"])*)"`)
	pySingleEsc = regexp.MustCompile(`\\[\\']`)
	pyDoubleEsc = regexp.MustCompile(`\\[\\'"abfnrtv]`)
)

func pyDotenvParse(t *testing.T, src string) map[string]string {
	out := map[string]string{}
	for len(src) > 0 {
		eq := strings.IndexByte(src, '=')
		if eq < 0 {
			t.Fatalf("python: no = in %q", src)
		}
		key := strings.TrimSpace(src[:eq])
		src = src[eq+1:]
		var v string
		switch {
		case strings.HasPrefix(src, "'"):
			m := pySingle.FindStringSubmatch(src)
			if m == nil {
				t.Fatalf("python: bad single-quoted value in %q", src)
			}
			v = pySingleEsc.ReplaceAllStringFunc(m[1], func(s string) string { return s[1:] })
			src = src[len(m[0]):]
		case strings.HasPrefix(src, `"`):
			m := pyDouble.FindStringSubmatch(src)
			if m == nil {
				t.Fatalf("python: bad double-quoted value in %q", src)
			}
			v = pyDoubleEsc.ReplaceAllStringFunc(m[1], func(s string) string {
				return map[byte]string{'\\': `\`, '\'': `'`, '"': `"`, 'a': "\a", 'b': "\b", 'f': "\f", 'n': "\n", 'r': "\r", 't': "\t", 'v': "\v"}[s[1]]
			})
			src = src[len(m[0]):]
		default:
			end := strings.IndexAny(src, "\r\n")
			if end < 0 {
				end = len(src)
			}
			v = src[:end]
			if i := strings.Index(v, " #"); i >= 0 {
				v = v[:i]
			}
			v = strings.TrimRight(v, " \t")
			src = src[end:]
		}
		// The rest of the line (only the newline here).
		if nl := strings.IndexByte(src, '\n'); nl >= 0 {
			src = src[nl+1:]
		} else {
			src = ""
		}
		out[key] = v
	}
	return out
}

// The known limits documented in export's help.
func nodeLimit(v string) bool {
	q := DotenvQuote([]byte(v))
	return strings.HasPrefix(q, `"`) && strings.ContainsAny(v, "\"\\")
}

func pyLimit(v string) bool {
	q := DotenvQuote([]byte(v))
	return strings.HasPrefix(q, "'") && strings.Contains(v, `\\`)
}

func TestDotenvQuoteRoundTripsThroughNodeAndPython(t *testing.T) {
	corpus := []string{
		"plain", "a-b_c.d/e:f@g%h+1,2=3", "", " ", "  lead and trail  ",
		"has space", `say "hi"`, "it's", "line1\nline2", "cr\rlf", "crlf\r\n", "tab\there",
		"#comment", "a # b", "a #b", "x#y", "$HOME", "${X}", "$$", "`cmd`", "`a` and 'b'",
		`back\slash`, `C:\dir\file`, `trailing\`, `\n literal`, `two\\backslashes`,
		"ünï cödé", "=leading equals", "quote \" and ' both", "it's a\nnewline",
		"it's \"quoted\"", "it's back\\slash", "json {\"a\": [1, 2]}", "multi\nline\nvalue with 'quote'",
		"tab\t'single'", "end with space ", "semi;colon&amp|pipe>gt<lt", "*glob?[x]", "!bang ~tilde ^caret",
	}
	for _, v := range corpus {
		line := "K=" + DotenvQuote([]byte(v)) + "\n"
		// Several lines in one file: values must not swallow their neighbours.
		src := "A=1\n" + line + "B='two'\n"
		node := nodeDotenvParse(src)
		py := pyDotenvParse(t, src)
		if node["A"] != "1" || node["B"] != "two" || py["A"] != "1" || py["B"] != "two" {
			t.Errorf("%q: neighbours broken: node %q, python %q", v, node, py)
		}
		if !nodeLimit(v) && node["K"] != v {
			t.Errorf("Node dotenv reads %s as %q, want %q", strings.TrimSpace(line), node["K"], v)
		}
		if !pyLimit(v) && py["K"] != v {
			t.Errorf("python-dotenv reads %s as %q, want %q", strings.TrimSpace(line), py["K"], v)
		}
	}
	// The limits are real, and only what the help says.
	if nodeDotenvParse("K=" + DotenvQuote([]byte("it's \"q\"")) + "\n")["K"] == "it's \"q\"" {
		t.Error("expected Node dotenv to keep \\\" in double quotes")
	}
	if pyDotenvParse(t, "K="+DotenvQuote([]byte(`a\\b`))+"\n")["K"] == `a\\b` {
		t.Error("expected python-dotenv to collapse \\\\ in single quotes")
	}
}

func TestDotenvQuoteChoices(t *testing.T) {
	cases := map[string]string{
		"plain":         "plain",
		"":              "''",
		"has space":     "'has space'",
		`say "hi"`:      `'say "hi"'`,
		"$HOME #x":      "'$HOME #x'",
		"it's":          `"it's"`,
		"a\nb":          `"a\nb"`,
		"a\rb":          `"a\rb"`,
		"it's \\ \"x\"": `"it's \\ \"x\""`,
	}
	for in, want := range cases {
		if got := DotenvQuote([]byte(in)); got != want {
			t.Errorf("DotenvQuote(%q) = %s, want %s", in, got, want)
		}
	}
}
