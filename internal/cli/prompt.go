package cli

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"
)

// MaxValueSize bounds a value read from stdin.
const MaxValueSize = 16 << 20

func isTerminal(f *os.File) bool { return term.IsTerminal(int(f.Fd())) }

// Confirm asks "<question> [y/N]" on the terminal. It returns nil when the
// user agrees or --yes was given. Without a terminal and without --yes it
// returns an exit-7 error; a "no" also returns exit 7. Print the plan
// before calling it.
func (c *Context) Confirm(question string) error {
	if c.Global.Yes {
		return nil
	}
	if !c.StdinIsTerminal {
		return &Error{Code: ExitNotConfirmed, Message: "confirmation needed, and there is no terminal to ask",
			Hint: "Read the plan above, then run the command again with --yes."}
	}
	fmt.Fprintf(c.Stderr, "%s [y/N] ", question)
	line, err := bufio.NewReader(c.Stdin).ReadString('\n')
	if err != nil && err != io.EOF {
		return err
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return nil
	}
	return &Error{Code: ExitNotConfirmed, Message: "not confirmed; nothing was changed"}
}

// ReadSecret reads a secret value: from a hidden prompt when stdin is a
// terminal, otherwise all of stdin with one trailing newline ("\n" or
// "\r\n") stripped. The value never comes from an argument. The caller
// should clear() the result when done.
func (c *Context) ReadSecret(prompt string) ([]byte, error) {
	if c.StdinIsTerminal {
		fmt.Fprint(c.Stderr, prompt)
		fd, err := c.stdinFd()
		if err != nil {
			return nil, err
		}
		v, err := term.ReadPassword(fd)
		fmt.Fprintln(c.Stderr)
		if err != nil {
			return nil, fmt.Errorf("reading the value: %w", err)
		}
		return v, nil
	}
	v, err := io.ReadAll(io.LimitReader(c.Stdin, MaxValueSize+1))
	if err != nil {
		return nil, fmt.Errorf("reading the value from stdin: %w", err)
	}
	if len(v) > MaxValueSize {
		clear(v)
		return nil, Errorf(ExitUsage, "the value on stdin is larger than %d bytes", MaxValueSize)
	}
	if bytes.HasSuffix(v, []byte("\r\n")) {
		v = v[:len(v)-2]
	} else if bytes.HasSuffix(v, []byte("\n")) {
		v = v[:len(v)-1]
	}
	return v, nil
}

// ReadPassphrase reads a passphrase: hidden, twice when confirm is set, on
// a terminal; otherwise the first line of stdin.
func (c *Context) ReadPassphrase(prompt string, confirm bool) (string, error) {
	if !c.StdinIsTerminal {
		line, err := bufio.NewReader(c.Stdin).ReadString('\n')
		if err != nil && err != io.EOF {
			return "", err
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			return "", Errorf(ExitUsage, "no passphrase on stdin")
		}
		return line, nil
	}
	fd, err := c.stdinFd()
	if err != nil {
		return "", err
	}
	fmt.Fprint(c.Stderr, prompt)
	p1, err := term.ReadPassword(fd)
	fmt.Fprintln(c.Stderr)
	if err != nil {
		return "", err
	}
	if len(p1) == 0 {
		return "", Errorf(ExitUsage, "the passphrase is empty")
	}
	if confirm {
		fmt.Fprint(c.Stderr, "Again: ")
		p2, err := term.ReadPassword(fd)
		fmt.Fprintln(c.Stderr)
		if err != nil {
			return "", err
		}
		if !bytes.Equal(p1, p2) {
			return "", Errorf(ExitUsage, "the passphrases do not match")
		}
	}
	return string(p1), nil
}

func (c *Context) stdinFd() (int, error) {
	f, ok := c.Stdin.(*os.File)
	if !ok {
		return 0, fmt.Errorf("stdin is not a terminal")
	}
	return int(f.Fd()), nil
}
