package config

import (
	"fmt"
	"regexp"
	"strings"
)

var (
	nameRe   = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*$`)
	secretRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	keyIDRe  = regexp.MustCompile(`^k[a-z0-9]{5}$`)
)

// ReservedPackageNames cannot be used as package names.
var ReservedPackageNames = []string{"carbon", "env"}

// MachinePrefix starts a machine reader or device id: "machine:<name>".
const MachinePrefix = "machine:"

// ValidName reports whether s is a valid package, environment, person,
// device, machine or team name: [a-z0-9][a-z0-9_-]*.
func ValidName(s string) bool { return nameRe.MatchString(s) }

// ValidSecretName reports whether s is a valid secret or var name (also the
// pattern for [env] keys): [A-Za-z_][A-Za-z0-9_]*.
func ValidSecretName(s string) bool { return secretRe.MatchString(s) }

// ValidKeyID reports whether s is a valid key id: "k" and 5 of [a-z0-9].
func ValidKeyID(s string) bool { return keyIDRe.MatchString(s) }

// CheckName returns an error naming what is wrong with a name of the given
// kind ("package", "environment", ...).
func CheckName(kind, s string) error {
	if !ValidName(s) {
		return fmt.Errorf("%s name %q is invalid: use lower-case letters, digits, '-' and '_', starting with a letter or digit", kind, s)
	}
	if kind == "package" {
		for _, r := range ReservedPackageNames {
			if s == r {
				return fmt.Errorf("package name %q is reserved", s)
			}
		}
	}
	return nil
}

// CheckSecretName returns an error if s is not a valid secret or var name.
func CheckSecretName(s string) error {
	if !ValidSecretName(s) {
		return fmt.Errorf("secret name %q is invalid: use letters, digits and '_', not starting with a digit", s)
	}
	return nil
}

// ScopeName renders "<package>/<env>".
func ScopeName(pkg, env string) string { return pkg + "/" + env }

// ParseScopeName splits "<package>/<env>" and validates both halves.
func ParseScopeName(s string) (pkg, env string, err error) {
	pkg, env, ok := strings.Cut(s, "/")
	if !ok || CheckName("package", pkg) != nil || !ValidName(env) {
		return "", "", fmt.Errorf("scope %q is not <package>/<env>", s)
	}
	return pkg, env, nil
}

// DeviceID renders a person's device as "<person>/<device>".
func DeviceID(person, device string) string { return person + "/" + device }

// MachineID renders a machine as "machine:<name>".
func MachineID(name string) string { return MachinePrefix + name }

// ValidDeviceID reports whether s is "<person>/<device>" or "machine:<name>".
func ValidDeviceID(s string) bool {
	if m, ok := strings.CutPrefix(s, MachinePrefix); ok {
		return ValidName(m)
	}
	p, d, ok := strings.Cut(s, "/")
	return ok && ValidName(p) && ValidName(d)
}

var trunkRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]*$`)

// CheckTrunk validates a trunk value: TrunkWorktree, or a git ref name that
// matches [A-Za-z0-9][A-Za-z0-9._/-]*, is not HEAD, and contains no "@",
// ":" or "..". The rule keeps a trunk name from being read as a git option,
// a revision expression, or the current branch.
func CheckTrunk(s string) error {
	if s == TrunkWorktree {
		return nil
	}
	if !trunkRe.MatchString(s) || s == "HEAD" || strings.Contains(s, "..") ||
		strings.ContainsAny(s, "@:") || strings.HasSuffix(s, "/") || strings.HasSuffix(s, ".lock") {
		return fmt.Errorf("trunk %q is not a plain git ref name (like origin/main) or %q", s, TrunkWorktree)
	}
	return nil
}
