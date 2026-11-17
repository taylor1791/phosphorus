package config

import (
	"fmt"
	"strings"
)

// RefKind is the kind of a ${...} reference in an [env] template.
type RefKind int

const (
	RefLocal     RefKind = iota + 1 // ${name}: this package's secret or var
	RefPackage                      // ${pkg.name}: another package's secret or var
	RefEnv                          // ${env:NAME}: the calling process's environment
	RefCarbonEnv                    // ${carbon.env}: the environment name
)

// Ref is one reference in a template.
type Ref struct {
	Kind    RefKind
	Package string // RefPackage only
	Name    string // secret/var name, or the variable for RefEnv
}

// Part is a literal run or a reference. Exactly one is set.
type Part struct {
	Literal string
	Ref     *Ref
}

// ParseTemplate parses an [env] value: ${name}, ${pkg.name}, ${env:NAME},
// ${carbon.env}, and $$ for a literal "$". Anything else after "$" is an
// error. Resolving references is the caller's job.
func ParseTemplate(s string) ([]Part, error) {
	var parts []Part
	var lit strings.Builder
	flush := func() {
		if lit.Len() > 0 {
			parts = append(parts, Part{Literal: lit.String()})
			lit.Reset()
		}
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '$' {
			lit.WriteByte(c)
			continue
		}
		if i+1 < len(s) && s[i+1] == '$' {
			lit.WriteByte('$')
			i++
			continue
		}
		if i+1 >= len(s) || s[i+1] != '{' {
			return nil, fmt.Errorf("at offset %d: '$' must start ${...} or be written $$", i)
		}
		end := strings.IndexByte(s[i+2:], '}')
		if end < 0 {
			return nil, fmt.Errorf("at offset %d: unterminated ${", i)
		}
		body := s[i+2 : i+2+end]
		ref, err := parseRef(body)
		if err != nil {
			return nil, err
		}
		flush()
		parts = append(parts, Part{Ref: ref})
		i += 2 + end
	}
	flush()
	return parts, nil
}

func parseRef(body string) (*Ref, error) {
	if name, ok := strings.CutPrefix(body, "env:"); ok {
		if !ValidSecretName(name) {
			return nil, fmt.Errorf("${%s}: %q is not a valid environment variable name", body, name)
		}
		return &Ref{Kind: RefEnv, Name: name}, nil
	}
	if body == "carbon.env" {
		return &Ref{Kind: RefCarbonEnv}, nil
	}
	if pkg, name, ok := strings.Cut(body, "."); ok {
		if CheckName("package", pkg) != nil || !ValidSecretName(name) {
			return nil, fmt.Errorf("${%s} is not ${package.name}", body)
		}
		return &Ref{Kind: RefPackage, Package: pkg, Name: name}, nil
	}
	if !ValidSecretName(body) {
		return nil, fmt.Errorf("${%s} is not a valid reference", body)
	}
	return &Ref{Kind: RefLocal, Name: body}, nil
}
