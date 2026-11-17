package cli

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/taylor1791/phosphorus/internal/resolve"
)

func init() {
	Register(&Command{
		Name:    "export",
		Usage:   "[--format dotenv|json] [-o <path>] [--env <env>] [--package <name>]",
		Summary: "Write resolved values to an ignored file",
		Help: `export resolves the package's [env] table, like run, and writes the variables
for tools that need a file. -o writes mode 0600 and refuses a path inside
the repository that git does not ignore; without -o, or with -o -, it
writes to stdout.

dotenv output is one NAME=value line per variable. A value made only of
letters, digits and _ . / : @ % + , = - is written bare; any other value is
double-quoted with backslash escapes for \ " $ and the backquote, and \n \r
\t for newline, carriage return and tab, so spaces, quotes, newlines, # and
$ survive.

With --json and -o, stdout gets a summary. With --json to stdout, the
output is the json format.`,
		Flags: func(fs *flag.FlagSet) {
			fs.String("format", "dotenv", "output `format`: dotenv or json")
			fs.String("o", "", "write to `path` (- for stdout)")
			fs.String("output", "", "")
		},
		Run: runExport,
	})
}

type exportResult struct {
	Scope     string   `json:"scope"`
	Path      string   `json:"path"`
	Format    string   `json:"format"`
	Variables []string `json:"variables"`
}

func runExport(c *Context) error {
	format := c.String("format")
	if format != "dotenv" && format != "json" {
		return c.UsageErr("unknown format %q: use dotenv or json", format)
	}
	out := c.String("o")
	if o := c.String("output"); o != "" {
		out = o
	}
	toStdout := out == "" || out == "-"
	if toStdout && c.JSON() {
		if c.Changed("format") && format != "json" {
			return c.UsageErr("--json writes JSON to stdout; use -o <path> for --format %s", format)
		}
		format = "json"
	}

	w, err := c.Workspace()
	if err != nil {
		return err
	}
	pkg, err := c.Package(w)
	if err != nil {
		return err
	}
	env, err := c.Environment(w)
	if err != nil {
		return err
	}

	var abs string
	if !toStdout {
		abs = out
		if !filepath.IsAbs(abs) {
			abs = filepath.Join(c.Cwd, abs)
		}
		if err := c.checkExportPath(w, out, abs); err != nil {
			return err
		}
	}

	res, err := c.resolvePackageEnv(w, pkg, env)
	if err != nil {
		return err
	}
	defer res.Zero()
	var data []byte
	if format == "json" {
		data, err = exportJSON(res)
		if err != nil {
			return err
		}
	} else {
		data = exportDotenv(res)
	}
	defer clear(data)

	if toStdout {
		_, err := c.Stdout.Write(data)
		return err
	}
	if err := writePrivate(abs, data); err != nil {
		return err
	}
	r := exportResult{Scope: pkg.Name + "/" + env, Path: w.Rel(abs), Format: format, Variables: []string{}}
	for _, v := range res.Vars {
		r.Variables = append(r.Variables, v.Name)
	}
	return c.Output(r, func(o io.Writer) {
		fmt.Fprintf(o, "Wrote %d variable(s) for %s to %s (mode 0600).\n", len(r.Variables), r.Scope, r.Path)
	})
}

// checkExportPath refuses a path inside the repository that git does not
// ignore. A path outside the work tree cannot be committed and is allowed.
func (c *Context) checkExportPath(w *Workspace, given, abs string) error {
	if fi, err := os.Stat(abs); err == nil && fi.IsDir() {
		return c.UsageErr("%s is a directory", given)
	}
	dir, err := filepath.EvalSymlinks(filepath.Dir(abs))
	if err != nil {
		return Errorf(ExitError, "cannot write %s: its directory does not exist", given).
			WithHint("Create the directory first.")
	}
	root, err := filepath.EvalSymlinks(w.Root)
	if err != nil {
		return err
	}
	full := filepath.Join(dir, filepath.Base(abs))
	rel, err := filepath.Rel(root, full)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return nil
	}
	ignored, err := w.Repo.IsIgnored(rel)
	if err != nil {
		return err
	}
	if !ignored {
		return &Error{Code: ExitUsage, Message: fmt.Sprintf("refusing to write secrets to %s: git does not ignore it", filepath.ToSlash(rel)),
			Details: []string{"A file git does not ignore can be committed, and then every value in it is in the history for good."},
			Hint:    fmt.Sprintf("Ignore it first, from the repository root:   echo %s >> .gitignore\nOr write to stdout:   carbon export > <file>", "/"+filepath.ToSlash(rel))}
	}
	return nil
}

// writePrivate writes data to path with mode 0600, atomically: a 0600
// temporary file in the same directory, renamed over the target.
func writePrivate(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".carbon-export-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	ok := false
	defer func() {
		if !ok {
			f.Close()
			os.Remove(tmp)
		}
	}()
	if err := f.Chmod(0o600); err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	ok = true
	return nil
}

func exportJSON(res *resolve.Result) ([]byte, error) {
	var b bytes.Buffer
	b.WriteString("{")
	for i, v := range res.Vars {
		if i > 0 {
			b.WriteString(",")
		}
		k, _ := json.Marshal(v.Name)
		val, err := json.Marshal(string(v.Value))
		if err != nil {
			return nil, err
		}
		fmt.Fprintf(&b, "\n  %s: %s", k, val)
		clear(val)
	}
	if len(res.Vars) > 0 {
		b.WriteString("\n")
	}
	b.WriteString("}\n")
	return b.Bytes(), nil
}

func exportDotenv(res *resolve.Result) []byte {
	var b bytes.Buffer
	for _, v := range res.Vars {
		b.WriteString(v.Name)
		b.WriteByte('=')
		b.WriteString(DotenvQuote(v.Value))
		b.WriteByte('\n')
	}
	return b.Bytes()
}

// DotenvQuote renders a dotenv value: bare when it is made only of safe
// characters, else double-quoted with \\ \" \$ \` \n \r \t escaped.
func DotenvQuote(v []byte) string {
	safe := len(v) > 0
	for _, c := range v {
		if !dotenvSafe(c) {
			safe = false
			break
		}
	}
	if safe {
		return string(v)
	}
	var b strings.Builder
	b.WriteByte('"')
	for _, c := range v {
		switch c {
		case '\\':
			b.WriteString(`\\`)
		case '"':
			b.WriteString(`\"`)
		case '$':
			b.WriteString(`\$`)
		case '`':
			b.WriteString("\\`")
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			b.WriteByte(c)
		}
	}
	b.WriteByte('"')
	return b.String()
}

func dotenvSafe(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	}
	return strings.IndexByte("_./:@%+,=-", c) >= 0
}
