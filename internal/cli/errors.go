package cli

import (
	"errors"
	"fmt"
	"strings"

	"github.com/taylor1791/phosphorus/internal/agewrap"
	"github.com/taylor1791/phosphorus/internal/config"
	"github.com/taylor1791/phosphorus/internal/gitx"
	"github.com/taylor1791/phosphorus/internal/scope"
)

// Exit codes. They are stable: scripts depend on them.
const (
	ExitOK           = 0
	ExitError        = 1 // unexpected error
	ExitUsage        = 2 // bad flags or arguments
	ExitNoAccess     = 3 // no access to a scope
	ExitCheckFailed  = 4 // `check` found errors
	ExitNotFound     = 5 // package, secret or person not found
	ExitNoIdentity   = 6 // no usable identity
	ExitNotConfirmed = 7 // a confirmation was refused or impossible
)

// Error is what a command returns to control how a failure is shown:
//
//	error: <Message>
//
//	  <Details[0]>
//	  <Details[1]>
//
//	  <Hint>
//
// Follow the design's style: Message says what happened, Details say why,
// Hint gives the next command. Never put a secret value in any field.
type Error struct {
	Code    int
	Message string
	Details []string
	Hint    string
	// Err is the underlying cause, for errors.Is/As. It is not printed;
	// put anything the user needs into Message or Details.
	Err error

	silent bool // already reported (e.g. usage printed); print nothing
}

func (e *Error) Error() string { return e.Message }
func (e *Error) Unwrap() error { return e.Err }

// Errorf makes an *Error with a code and a formatted message.
func Errorf(code int, format string, args ...any) *Error {
	return &Error{Code: code, Message: fmt.Sprintf(format, args...)}
}

// WithDetail appends detail lines and returns e.
func (e *Error) WithDetail(lines ...string) *Error {
	e.Details = append(e.Details, lines...)
	return e
}

// WithHint sets the hint and returns e.
func (e *Error) WithHint(format string, args ...any) *Error {
	e.Hint = fmt.Sprintf(format, args...)
	return e
}

// WithCause records the underlying error and returns e.
func (e *Error) WithCause(err error) *Error {
	e.Err = err
	return e
}

// AsError converts any error into an *Error, mapping the errors that the
// internal packages return to the right exit code and advice.
func AsError(err error) *Error {
	var e *Error
	if errors.As(err, &e) {
		return e
	}
	var legacy *config.LegacyError
	if errors.As(err, &legacy) {
		return LegacyErr(legacy.Path)
	}
	var conflict *config.ConflictError
	if errors.As(err, &conflict) {
		return ConflictErr(conflict.Path)
	}
	switch {
	case errors.Is(err, gitx.ErrNotRepo):
		return &Error{Code: ExitError, Message: "not inside a git repository", Err: err,
			Hint: "carbon keeps secrets in a git repository. Run `git init` first, or use -C <dir>."}
	case errors.Is(err, agewrap.ErrBadPassphrase):
		return &Error{Code: ExitNoIdentity, Message: "incorrect passphrase for your identity", Err: err}
	case errors.Is(err, scope.ErrInboxMismatch):
		return &Error{Code: ExitError, Message: "the scope's inbox key was replaced", Err: err,
			Details: []string{err.Error()},
			Hint:    "Restore the keys file from trunk (git checkout <trunk> -- <keys file>) and find out who changed it."}
	case errors.Is(err, scope.ErrTampered):
		return &Error{Code: ExitError, Message: "a stored secret or key failed authentication", Err: err,
			Details: []string{err.Error()},
			Hint:    "Look at the git history of the file for an edited or copied line, and restore it."}
	}
	return &Error{Code: ExitError, Message: err.Error(), Err: err}
}

// LegacyErr is the error for a carbon 0.0.3 repository.
func LegacyErr(path string) *Error {
	return &Error{
		Code:    ExitError,
		Message: "this repository uses carbon 0.0.3",
		Details: []string{path + " has a [push] or [pull] table. Carbon 1.0 reads a different format."},
		Hint:    "Migrate it with carbon-migrate, which converts the files and re-seals every secret.",
	}
}

// ConflictErr is the error for a file with git conflict markers.
func ConflictErr(path string) *Error {
	e := &Error{
		Code:    ExitError,
		Message: path + " has unresolved git conflict markers",
		Details: []string{"carbon will not read a file in the middle of a merge."},
		Hint:    "Resolve the conflict by keeping one side of each conflicting line, then run the command again.",
	}
	if strings.HasSuffix(path, ".keys.toml") {
		e.Hint += "\nIf both sides rotated the key, keep either side and run `carbon apply` to rotate once more."
	}
	return e
}

// UsageErr is a usage error with a hint pointing at the command's help.
func (c *Context) UsageErr(format string, args ...any) *Error {
	e := Errorf(ExitUsage, format, args...)
	if c.Command != nil {
		e.Hint = "Usage: " + usageLine(c.Command)
	}
	return e
}
