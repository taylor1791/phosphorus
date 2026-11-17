package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unicode/utf8"

	"github.com/taylor1791/phosphorus/internal/resolve"
)

func init() {
	Register(&Command{
		Name:    "export",
		Group:   GroupDaily,
		Usage:   "[--format dotenv|json] [-o <path>] [--env <env>] [--package <name>]",
		Summary: "Write resolved values to an ignored file",
		Help: `export resolves the package's [env] table, like run, and writes the variables
for tools that need a file. -o writes mode 0600 and refuses a path inside
the repository that git does not ignore; without -o, or with -o -, it
writes to stdout.

dotenv output is one NAME=value line per variable, written for the Node
dotenv package (v16 and later) and python-dotenv:

  - a value made only of letters, digits and _ . / : @ % + , = - is bare;
  - any other value without a single quote, newline or carriage return,
    and not ending in a backslash, is in single quotes, which both read
    literally;
  - the rest are in double quotes with \\ \" \n \r escaped.

Known limits: python-dotenv reads \\ inside single quotes as one
backslash; Node dotenv keeps \" and \\ inside double quotes as written; and
python-dotenv expands ${NAME} inside values unless loaded with
interpolate=False. Use --format json when a value has both a quote or
newline and a backslash or double quote.

json output is one object of strings; a value that is not UTF-8 is refused.
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
	inRepo := false
	if !toStdout {
		abs = out
		if !filepath.IsAbs(abs) {
			abs = filepath.Join(c.Cwd, abs)
		}
		if inRepo, err = c.checkExportPath(w, out, abs); err != nil {
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
	tmpDir := filepath.Dir(abs)
	if inRepo {
		// Never leave a temporary file in the work tree, where it would
		// not be ignored: git never adds anything inside its own directory.
		if tmpDir, err = w.Repo.GitDir(); err != nil {
			return err
		}
	}
	if err := writePrivate(abs, tmpDir, data); err != nil {
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
// ignore, and reports whether the path is inside the work tree. A path
// outside the work tree cannot be committed and is allowed.
func (c *Context) checkExportPath(w *Workspace, given, abs string) (bool, error) {
	if fi, err := os.Stat(abs); err == nil && fi.IsDir() {
		return false, c.UsageErr("%s is a directory", given)
	}
	dir, err := filepath.EvalSymlinks(filepath.Dir(abs))
	if err != nil {
		return false, Errorf(ExitError, "cannot write %s: its directory does not exist", given).
			WithHint("Create the directory first.")
	}
	root, err := filepath.EvalSymlinks(w.Root)
	if err != nil {
		return false, err
	}
	full := filepath.Join(dir, filepath.Base(abs))
	rel, err := filepath.Rel(root, full)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return false, nil
	}
	ignored, err := w.Repo.IsIgnored(rel)
	if err != nil {
		return false, err
	}
	if !ignored {
		return false, &Error{Code: ExitUsage, Message: fmt.Sprintf("refusing to write secrets to %s: git does not ignore it", filepath.ToSlash(rel)),
			Details: []string{"A file git does not ignore can be committed, and then every value in it is in the history for good."},
			Hint:    fmt.Sprintf("Ignore it first, from the repository root:   echo %s >> .gitignore\nOr write to stdout:   carbon export > <file>", "/"+filepath.ToSlash(rel))}
	}
	return true, nil
}

// writePrivate writes data to path with mode 0600: a 0600 temporary file in
// tmpDir, renamed over the target (which replaces a symlink rather than
// writing through it). When tmpDir is on another filesystem the rename
// fails, and the target is written directly instead: created 0600, never
// through a symlink, its mode forced to 0600 before any data is written.
func writePrivate(path, tmpDir string, data []byte) error {
	f, err := os.CreateTemp(tmpDir, "carbon-export-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp) // a no-op after a successful rename
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	err = os.Rename(tmp, path)
	if err == nil {
		return nil
	}
	if !errors.Is(err, syscall.EXDEV) {
		return err
	}
	return writeDirect(path, data)
}

func writeDirect(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return err
	}
	if err := f.Truncate(0); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func exportJSON(res *resolve.Result) ([]byte, error) {
	var b bytes.Buffer
	b.WriteString("{")
	for i, v := range res.Vars {
		if !utf8.Valid(v.Value) {
			clear(b.Bytes())
			return nil, &Error{Code: ExitError, Message: fmt.Sprintf("%s is not UTF-8 text, so JSON cannot hold it unchanged", v.Name),
				Hint: "Store such values base64-encoded, or use --format dotenv."}
		}
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

// DotenvQuote renders a dotenv value for Node dotenv (v16+) and
// python-dotenv: bare when it is made only of safe characters; in single
// quotes (read literally by both) when it has no single quote, newline or
// carriage return and does not end in a backslash; else in double quotes with \\ \" \n \r escaped. See the
// export help for the known limits.
func DotenvQuote(v []byte) string {
	safe := len(v) > 0
	single := true
	for _, c := range v {
		if !dotenvSafe(c) {
			safe = false
		}
		if c == '\'' || c == '\n' || c == '\r' {
			single = false
		}
	}
	if len(v) > 0 && v[len(v)-1] == '\\' {
		// python-dotenv would read \' as an escaped quote and run on into
		// the next line.
		single = false
	}
	switch {
	case safe:
		return string(v)
	case single:
		return "'" + string(v) + "'"
	}
	var b strings.Builder
	b.WriteByte('"')
	for _, c := range v {
		switch c {
		case '\\':
			b.WriteString(`\\`)
		case '"':
			b.WriteString(`\"`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
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
