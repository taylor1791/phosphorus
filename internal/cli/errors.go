package cli

import (
	"errors"
	"fmt"
	"strings"

	"github.com/taylor1791/phosphorus/internal/agewrap"
	"github.com/taylor1791/phosphorus/internal/config"
	"github.com/taylor1791/phosphorus/internal/gitx"
	"github.com/taylor1791/phosphorus/internal/policy"
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
	var missing *policy.TrunkMissingError
	if errors.As(err, &missing) {
		return &Error{Code: ExitError, Message: missing.Error(), Err: err,
			Details: []string{"carbon reads access policy and inbox keys from trunk, and will not fall back to the working tree while this clone has remotes."},
			Hint:    "Fetch it:   git fetch\nOr choose another trunk for this clone:   git config " + policy.TrunkConfigKey + " <ref>"}
	}
	var notrunk *policy.NoTrunkError
	if errors.As(err, &notrunk) {
		return &Error{Code: ExitError, Message: notrunk.Error(), Err: err,
			Details: []string{"carbon reads access policy and inbox keys from trunk: the remote default branch unless CARBON_TRUNK or git config " + policy.TrunkConfigKey + " says otherwise."},
			Hint:    "Record the remote default:   git remote set-head origin -a\nOr fetch:   git fetch\nOr choose it:   git config " + policy.TrunkConfigKey + " <ref>"}
	}
	if errors.Is(err, config.ErrTrunkSettingRemoved) {
		return &Error{Code: ExitError, Message: "carbon.toml still has [workspace] trunk, which was removed", Err: err,
			Details: []string{"The trunk ref is chosen per clone, never by a commit: CARBON_TRUNK, then git config " + policy.TrunkConfigKey + ", then the remote default branch."},
			Hint:    "Delete the trunk line from carbon.toml. If this clone needs a trunk other than the remote default:   git config " + policy.TrunkConfigKey + " <ref>"}
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
		e.Hint = "Resolve the conflict by keeping one side of each conflicting line; each line is self-contained:\n" +
			"- Both sides added a slot for the same device (two applies): keep either line; both wrap the same key.\n" +
			"- Both sides rotated the key: keep either side's whole file (and the same side's secrets file), then run `carbon apply` to rotate once more."
	}
	if strings.HasSuffix(path, ".secrets.toml") {
		e.Hint = "Resolve the conflict by keeping one side of each conflicting line; each line is self-contained:\n" +
			"- One side rotated the key (every line re-sealed) and the other added or set secrets: keep the rotated side's lines,\n" +
			"  then add back each line the other side added or changed, exactly as it was. It still opens through the retired key,\n" +
			"  and the next `carbon apply` lists it and re-seals it under the current key.\n" +
			"- Both sides set the same secret: keep either line; each is a valid value or drop."
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
