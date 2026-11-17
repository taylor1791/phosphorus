package migrate

import (
	"fmt"
	"regexp"
	"strings"
)

// Carbon 1.0 name rules, from docs/implementation.md ("Names").
var (
	nameRe   = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*$`)
	secretRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	bareKey  = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
)

var reservedPackages = map[string]bool{"carbon": true, "env": true}

func validName(s string) bool   { return nameRe.MatchString(s) }
func validSecret(s string) bool { return secretRe.MatchString(s) }

// slugName turns s into a valid package, environment or person name.
func slugName(s string) string {
	var b strings.Builder
	dash := false
	for _, r := range strings.ToLower(s) {
		ok := r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_' || r == '-'
		if !ok {
			if !dash && b.Len() > 0 {
				b.WriteByte('-')
			}
			dash = true
			continue
		}
		b.WriteRune(r)
		dash = false
	}
	out := strings.TrimLeft(strings.TrimRight(b.String(), "-"), "-_")
	if out == "" {
		out = "x"
	}
	return out
}

// slugSecret turns s into a valid secret, var or [env] name.
func slugSecret(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	out := b.String()
	if out == "" || out[0] >= '0' && out[0] <= '9' {
		out = "_" + out
	}
	return out
}

// quote renders s as a TOML basic string.
func quote(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"':
			b.WriteString(`\"`)
		case r == '\\':
			b.WriteString(`\\`)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\t':
			b.WriteString(`\t`)
		case r == '\r':
			b.WriteString(`\r`)
		case r < 0x20 || r == 0x7f:
			fmt.Fprintf(&b, `\u%04X`, r)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

// tomlKey renders a key bare when it can be.
func tomlKey(s string) string {
	if bareKey.MatchString(s) {
		return s
	}
	return quote(s)
}

// comment renders text as TOML comment lines.
func comment(prefix, text string) string {
	var b strings.Builder
	for _, l := range strings.Split(text, "\n") {
		b.WriteString("# ")
		b.WriteString(prefix)
		b.WriteString(l)
		b.WriteByte('\n')
		prefix = strings.Repeat(" ", len(prefix))
	}
	return b.String()
}
