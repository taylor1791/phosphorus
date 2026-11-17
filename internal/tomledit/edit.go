// Package tomledit makes small, comment-preserving edits to TOML files that
// people write (carbon.toml, .carbon/teams.toml, people files).
//
// Every operation changes only the bytes it must: comments, ordering,
// spacing and quoting elsewhere stay as they were. After each edit the
// result is parsed again with the real TOML parser and compared with the
// intended semantic change; if the two differ, or the file has a shape the
// editor cannot change safely (a value inside an inline table it would have
// to restructure, an array of tables, a comment in the way), the operation
// fails with an [*Error] that says exactly what to edit by hand, and the
// document is left unchanged.
package tomledit

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"strings"

	"github.com/pelletier/go-toml/v2"
)

// Error is an edit the editor will not make. Manual says what to change by
// hand.
type Error struct {
	File   string
	Reason string
	Manual string
}

func (e *Error) Error() string {
	msg := fmt.Sprintf("cannot edit %s safely: %s", e.File, e.Reason)
	if e.Manual != "" {
		msg += "; edit it by hand: " + e.Manual
	}
	return msg
}

// Doc is a TOML document being edited.
type Doc struct {
	name string
	src  []byte
	idx  *index
}

// Parse parses src. name is used in errors.
func Parse(name string, src []byte) (*Doc, error) {
	d := &Doc{name: name, src: append([]byte(nil), src...)}
	if _, err := d.semantic(d.src); err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	ix, err := scan(d.src)
	if err != nil {
		return nil, &Error{File: name, Reason: "the file has a layout this editor does not understand (" + err.Error() + ")"}
	}
	d.idx = ix
	return d, nil
}

// Bytes returns the document.
func (d *Doc) Bytes() []byte { return append([]byte(nil), d.src...) }

func (d *Doc) semantic(src []byte) (map[string]any, error) {
	m := map[string]any{}
	if err := toml.Unmarshal(src, &m); err != nil {
		return nil, err
	}
	return m, nil
}

// lookup returns the parsed value at path.
func (d *Doc) lookup(path []string) (any, bool) {
	m, err := d.semantic(d.src)
	if err != nil {
		return nil, false
	}
	return get(m, path)
}

func get(m map[string]any, path []string) (any, bool) {
	var cur any = m
	for _, k := range path {
		t, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		if cur, ok = t[k]; !ok {
			return nil, false
		}
	}
	return cur, true
}

// set sets path in m, creating tables; it reports false if a parent is not
// a table.
func set(m map[string]any, path []string, v any) bool {
	for _, k := range path[:len(path)-1] {
		next, ok := m[k]
		if !ok {
			n := map[string]any{}
			m[k] = n
			m = n
			continue
		}
		if m, ok = next.(map[string]any); !ok {
			return false
		}
	}
	m[path[len(path)-1]] = v
	return true
}

func del(m map[string]any, path []string) {
	parent, ok := get(m, path[:len(path)-1])
	if t, ok2 := parent.(map[string]any); ok && ok2 {
		delete(t, path[len(path)-1])
	}
}

// Has reports whether path exists (as any value or table).
func (d *Doc) Has(path ...string) bool { _, ok := d.lookup(path); return ok }

// Kind returns "array", "table", "string", "other", or "" if path does
// not exist.
func (d *Doc) Kind(path ...string) string {
	v, ok := d.lookup(path)
	if !ok {
		return ""
	}
	switch v.(type) {
	case []any:
		return "array"
	case map[string]any:
		return "table"
	case string:
		return "string"
	}
	return "other"
}

// Strings returns the strings of the array at path.
func (d *Doc) Strings(path ...string) ([]string, bool) {
	v, ok := d.lookup(path)
	arr, ok2 := v.([]any)
	if !ok || !ok2 {
		return nil, false
	}
	var out []string
	for _, x := range arr {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out, true
}

// Keys returns the keys of the table at path.
func (d *Doc) Keys(path ...string) []string {
	v, _ := d.lookup(path)
	t, _ := v.(map[string]any)
	var out []string
	for k := range t {
		out = append(out, k)
	}
	sortStrings(out)
	return out
}

// String returns the string at path.
func (d *Doc) String(path ...string) (string, bool) {
	v, ok := d.lookup(path)
	s, ok2 := v.(string)
	return s, ok && ok2
}

// commit replaces the document with next after checking that next parses
// and equals the original with change applied.
func (d *Doc) commit(next []byte, change func(m map[string]any) bool, manual string) error {
	want, err := d.semantic(d.src)
	if err != nil {
		return err
	}
	if !change(want) {
		return d.refuse("the value is not where the editor expected it", manual)
	}
	got, err := d.semantic(next)
	if err != nil {
		return d.refuse("the edited file would not parse ("+firstLine(err.Error())+")", manual)
	}
	if !reflect.DeepEqual(want, got) {
		return d.refuse("the edit would change more than intended", manual)
	}
	ix, err := scan(next)
	if err != nil {
		return d.refuse("the edited file has a layout this editor does not understand", manual)
	}
	d.src, d.idx = next, ix
	return nil
}

func firstLine(s string) string { l, _, _ := strings.Cut(s, "\n"); return l }

func (d *Doc) refuse(reason, manual string) error {
	return &Error{File: d.name, Reason: reason, Manual: manual}
}

func describe(path []string) string {
	if len(path) == 0 {
		return "the top of the file"
	}
	if len(path) == 1 {
		return path[0]
	}
	return "[" + strings.Join(path[:len(path)-1], ".") + "] " + path[len(path)-1]
}

func (d *Doc) node(path []string) *node { return d.idx.nodes[pathKey(path)] }

func splice(src []byte, start, end int, repl string) []byte {
	out := make([]byte, 0, len(src)-(end-start)+len(repl))
	out = append(out, src[:start]...)
	out = append(out, repl...)
	return append(out, src[end:]...)
}

// lineStart returns the offset of the start of the line containing off.
func lineStart(src []byte, off int) int {
	return bytes.LastIndexByte(src[:off], '\n') + 1
}

// lineEnd returns the offset just past the newline ending the line
// containing off (or len(src)).
func lineEnd(src []byte, off int) int {
	if i := bytes.IndexByte(src[off:], '\n'); i >= 0 {
		return off + i + 1
	}
	return len(src)
}

func onlySpace(b []byte) bool { return len(bytes.Trim(b, " \t")) == 0 }

// restIsTrivia reports whether src[off:] up to the end of its line is
// only spaces, an optional comma (when comma is set), and an optional
// comment.
func restIsTrivia(src []byte, off int, comma bool) (int, bool) {
	i := off
	for i < len(src) && (src[i] == ' ' || src[i] == '\t') {
		i++
	}
	if comma && i < len(src) && src[i] == ',' {
		i++
		for i < len(src) && (src[i] == ' ' || src[i] == '\t') {
			i++
		}
	}
	if i < len(src) && src[i] == '#' {
		for i < len(src) && src[i] != '\n' {
			i++
		}
	}
	if i < len(src) && src[i] == '\r' {
		i++
	}
	if i == len(src) || src[i] == '\n' {
		return i, true
	}
	return i, false
}

func hasComment(b []byte) bool { return bytes.IndexByte(b, '#') >= 0 }

// Quote renders s as a TOML basic string.
func Quote(s string) string {
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

var bareKey = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// Key renders a key: bare when possible, else quoted.
func Key(k string) string {
	if bareKey.MatchString(k) {
		return k
	}
	return Quote(k)
}

// Render renders a value: a string, a []string, a bool or an int.
func Render(v any) (string, error) {
	switch v := v.(type) {
	case string:
		return Quote(v), nil
	case []string:
		q := make([]string, len(v))
		for i, s := range v {
			q[i] = Quote(s)
		}
		return "[" + strings.Join(q, ", ") + "]", nil
	case bool:
		if v {
			return "true", nil
		}
		return "false", nil
	case int:
		return fmt.Sprint(v), nil
	}
	return "", fmt.Errorf("tomledit cannot render a %T", v)
}

// semanticValue is what the real parser returns for a rendered value.
func semanticValue(v any) any {
	switch v := v.(type) {
	case []string:
		out := make([]any, len(v))
		for i, s := range v {
			out[i] = s
		}
		return out
	case int:
		return int64(v)
	}
	return v
}

// ArrayAdd appends s to the array of strings at path unless it is already
// there, and reports whether it changed the document.
func (d *Doc) ArrayAdd(path []string, s string) (bool, error) {
	manual := fmt.Sprintf("add %s to the list %s", Quote(s), describe(path))
	cur, ok := d.Strings(path...)
	if !ok {
		return false, d.refuse(describe(path)+" is not a list", manual)
	}
	for _, x := range cur {
		if x == s {
			return false, nil
		}
	}
	n := d.node(path)
	if n == nil || n.kind != 'a' {
		return false, d.refuse(describe(path)+" is not written where the editor can find it", manual)
	}
	src := d.src
	var next []byte
	switch {
	case len(n.elems) == 0:
		inner := src[n.start+1 : n.end-1]
		if hasComment(inner) {
			return false, d.refuse("the empty list holds a comment", manual)
		}
		next = splice(src, n.start, n.end, "["+Quote(s)+"]")
	default:
		last := n.elems[len(n.elems)-1]
		closeLine := lineStart(src, n.end-1)
		multiline := bytes.IndexByte(src[n.start:n.end], '\n') >= 0
		ownLine := onlySpace(src[closeLine : n.end-1])
		lastStart := lineStart(src, last.start)
		lastOwn := onlySpace(src[lastStart:last.start]) && lastStart > lineStart(src, n.start)
		if multiline && ownLine && lastOwn {
			indent := string(src[lastStart:last.start])
			// Is there a comma after the last element?
			i := last.end
			for i < len(src) && (src[i] == ' ' || src[i] == '\t') {
				i++
			}
			trailingComma := i < len(src) && src[i] == ','
			end, ok := restIsTrivia(src, last.end, true)
			if !ok {
				return false, d.refuse("the list's last line holds more than one value", manual)
			}
			insertAt := end
			if insertAt < len(src) {
				insertAt++ // past the newline
			}
			line := indent + Quote(s)
			if trailingComma {
				next = splice(src, insertAt, insertAt, line+",\n")
			} else {
				next = splice(src, insertAt, insertAt, line+"\n")
				next = splice(next, last.end, last.end, ",")
			}
		} else {
			next = splice(src, last.end, last.end, ", "+Quote(s))
		}
	}
	return true, d.commit(next, func(m map[string]any) bool {
		v, _ := get(m, path)
		arr, ok := v.([]any)
		if !ok {
			return false
		}
		return set(m, path, append(arr, s))
	}, manual)
}

// ArrayRemove removes every occurrence of s from the array of strings at
// path and reports whether it changed the document.
func (d *Doc) ArrayRemove(path []string, s string) (bool, error) {
	manual := fmt.Sprintf("remove %s from the list %s", Quote(s), describe(path))
	cur, ok := d.Strings(path...)
	if !ok {
		if d.Has(path...) {
			return false, d.refuse(describe(path)+" is not a list", manual)
		}
		return false, nil
	}
	count := 0
	for _, x := range cur {
		if x == s {
			count++
		}
	}
	if count == 0 {
		return false, nil
	}
	for ; count > 0; count-- {
		if err := d.removeOne(path, s, manual); err != nil {
			return false, err
		}
	}
	return true, nil
}

func (d *Doc) removeOne(path []string, s, manual string) error {
	n := d.node(path)
	if n == nil || n.kind != 'a' {
		return d.refuse(describe(path)+" is not written where the editor can find it", manual)
	}
	at := -1
	for i, e := range n.elems {
		if e.isStr && e.str == s {
			at = i
			break
		}
	}
	if at < 0 {
		return d.refuse(Quote(s)+" is written in a form the editor does not read", manual)
	}
	src := d.src
	e := n.elems[at]
	var start, end int
	lineMode := false
	ls := lineStart(src, e.start)
	if onlySpace(src[ls:e.start]) && ls > lineStart(src, n.start) {
		// The element starts its line; if the rest of the line is only a
		// comma and a comment, the line is the element's alone.
		if stop, ok := restIsTrivia(src, e.end, true); ok {
			start, end, lineMode = ls, lineEnd(src, stop), true
		}
	}
	if !lineMode {
		switch {
		case len(n.elems) == 1:
			// Delete the element and any trailing comma.
			start, end = e.start, e.end
			i := e.end
			for i < n.end-1 && (src[i] == ' ' || src[i] == '\t') {
				i++
			}
			if src[i] == ',' {
				end = i + 1
			}
		case at < len(n.elems)-1:
			start, end = e.start, n.elems[at+1].start
		default:
			start, end = n.elems[at-1].end, e.end
		}
		if hasComment(src[start:end]) {
			return d.refuse("a comment sits next to "+Quote(s), manual)
		}
	}
	next := splice(src, start, end, "")
	return d.commit(next, func(m map[string]any) bool {
		v, _ := get(m, path)
		arr, ok := v.([]any)
		if !ok {
			return false
		}
		out := []any{}
		removed := false
		for _, x := range arr {
			if !removed && x == any(s) {
				removed = true
				continue
			}
			out = append(out, x)
		}
		return set(m, path, out)
	}, manual)
}

// SetString replaces the string at path with s.
func (d *Doc) SetString(path []string, s string) error {
	manual := fmt.Sprintf("set %s to %s", describe(path), Quote(s))
	if d.Kind(path...) != "string" {
		return d.refuse(describe(path)+" is not a string", manual)
	}
	n := d.node(path)
	if n == nil {
		return d.refuse(describe(path)+" is not written where the editor can find it", manual)
	}
	next := splice(d.src, n.start, n.end, Quote(s))
	return d.commit(next, func(m map[string]any) bool { return set(m, path, s) }, manual)
}

// RemoveKey deletes the line holding the key at path and reports whether
// it existed. The key must be a statement on its own line(s), not a value
// inside an inline table.
func (d *Doc) RemoveKey(path []string) (bool, error) {
	manual := "delete the line " + describe(path)
	if !d.Has(path...) {
		return false, nil
	}
	n := d.node(path)
	if n == nil || !n.lineKV {
		return false, d.refuse(describe(path)+" is not a line of its own (it may be inside an inline table or a [table] header)", manual)
	}
	ls := lineStart(d.src, n.keyStart)
	if !onlySpace(d.src[ls:n.keyStart]) {
		return false, d.refuse(describe(path)+" shares its line", manual)
	}
	stop, ok := restIsTrivia(d.src, n.end, false)
	if !ok {
		return false, d.refuse(describe(path)+" shares its line", manual)
	}
	next := splice(d.src, ls, lineEnd(d.src, stop), "")
	return true, d.commit(next, func(m map[string]any) bool { del(m, path); return true }, manual)
}

// EnsureTable adds a [table] header at the end of the file unless the
// table exists.
func (d *Doc) EnsureTable(table []string) error {
	if len(table) == 0 || d.Has(table...) {
		if len(table) > 0 && d.Kind(table...) != "table" {
			return d.refuse(describe(table)+" is not a table", "")
		}
		return nil
	}
	keys := make([]string, len(table))
	for i, k := range table {
		keys[i] = Key(k)
	}
	header := "[" + strings.Join(keys, ".") + "]\n"
	src := d.src
	prefix := ""
	if len(src) > 0 && src[len(src)-1] != '\n' {
		prefix = "\n"
	}
	if len(src) > 0 {
		prefix += "\n"
	}
	next := append(append([]byte(nil), src...), prefix+header...)
	return d.commit(next, func(m map[string]any) bool { return set(m, table, map[string]any{}) },
		"add a line "+strings.TrimSpace(header))
}

// SetKey adds key = value to table (creating the table at the end of the
// file if it is missing). The key must not exist yet. value is a string,
// []string, bool or int.
func (d *Doc) SetKey(table []string, key string, value any) error {
	rendered, err := Render(value)
	if err != nil {
		return err
	}
	line := Key(key) + " = " + rendered
	where := "at the top of the file"
	if len(table) > 0 {
		where = "under [" + strings.Join(table, ".") + "]"
	}
	manual := fmt.Sprintf("add the line %s %s", line, where)
	full := append(append([]string{}, table...), key)
	if d.Has(full...) {
		return d.refuse(describe(full)+" already exists", manual)
	}
	if err := d.EnsureTable(table); err != nil {
		var e *Error
		if errors.As(err, &e) {
			e.Manual = manual
		}
		return err
	}
	var sec *section
	for _, s := range d.idx.sections {
		root := len(table) == 0 && s.header < 0
		header := len(table) > 0 && s.header >= 0 && !s.array && reflect.DeepEqual(s.path, table)
		if root || header {
			sec = s
			break
		}
	}
	if sec == nil {
		return d.refuse("["+strings.Join(table, ".")+"] is defined by dotted keys or an inline table, not a header", manual)
	}
	at := sec.lastEnd
	if at < 0 {
		at = sec.headerEnd
	}
	src := d.src
	prefix := ""
	if at > 0 && src[at-1] != '\n' {
		prefix = "\n"
	}
	next := splice(src, at, at, prefix+line+"\n")
	return d.commit(next, func(m map[string]any) bool { return set(m, full, semanticValue(value)) }, manual)
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}
