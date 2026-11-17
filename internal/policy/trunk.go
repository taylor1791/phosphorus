package policy

import (
	"errors"
	"fmt"
	"io/fs"

	"github.com/taylor1791/phosphorus/internal/config"
	"github.com/taylor1791/phosphorus/internal/gitx"
)

// TrunkConfigKey is the local git config key that overrides the trunk ref.
const TrunkConfigKey = "carbon.trunk"

// TrunkEnv overrides the trunk ref for one process.
const TrunkEnv = "CARBON_TRUNK"

// Where a trunk came from (Trunk.From).
const (
	TrunkFromEnv       = "CARBON_TRUNK"                 // the environment variable
	TrunkFromGitConfig = "git config " + TrunkConfigKey // the clone's git config
	TrunkFromRemote    = "remote default branch"        // origin/HEAD, else origin/main, else origin/master
	TrunkFromNone      = "none"                         // no override and no remote: a new local repository
)

// Trunk is the trunk ref this clone uses and where it came from. Nothing a
// commit can change chooses it: the order is CARBON_TRUNK, then the local
// git config carbon.trunk (each a ref or "worktree"), then the remote default
// branch. carbon never writes git config itself.
type Trunk struct {
	// Ref is the full branch refname (refs/remotes/... or refs/heads/...,
	// never a tag), config.TrunkWorktree, or "" when From is TrunkFromNone.
	Ref string
	// Name is the value as configured (CARBON_TRUNK or git config), before
	// it was resolved to Ref.
	Name string
	// Commit is the commit Ref pointed to when it was resolved, once per
	// command. Every read of trunk uses it.
	Commit string
	// From is one of the TrunkFrom* constants.
	From string
}

// IsWorktree reports whether policy is read from the working tree always.
func (t *Trunk) IsWorktree() bool { return t.Ref == config.TrunkWorktree }

// IsOverride reports whether the trunk came from CARBON_TRUNK or git config.
func (t *Trunk) IsOverride() bool { return t.From == TrunkFromEnv || t.From == TrunkFromGitConfig }

func (t *Trunk) String() string {
	if t.From == TrunkFromNone {
		return "none (no remote, no " + TrunkConfigKey + ")"
	}
	return fmt.Sprintf("%s (from %s)", t.Display(), t.From)
}

// Display is the full ref and the short commit id, as carbon shows trunk.
func (t *Trunk) Display() string {
	if t.Commit == "" {
		return t.Ref
	}
	c := t.Commit
	if len(c) > 7 {
		c = c[:7]
	}
	return t.Ref + " at " + c
}

// At is what git reads trunk files from: the commit when resolved, else
// the ref.
func (t *Trunk) At() string {
	if t.Commit != "" {
		return t.Commit
	}
	return t.Ref
}

// TrunkMissingError means the chosen trunk ref does not resolve: an override
// that names a missing ref, or a remote default that points nowhere. It is
// never a silent fall back to the working tree.
type TrunkMissingError struct{ Ref, From string }

func (e *TrunkMissingError) Error() string {
	return fmt.Sprintf("trunk %s (from %s) does not exist in this clone", e.Ref, e.From)
}

// NoTrunkError means the repository has remote-tracking refs, but none of
// origin/HEAD, origin/main, origin/master, and there is no override.
type NoTrunkError struct{}

func (e *NoTrunkError) Error() string {
	return "cannot tell which branch is trunk: this clone has remotes but no origin/HEAD, origin/main or origin/master"
}

// ResolveTrunk chooses the trunk ref as described on [Trunk]. getenv is
// usually os.Getenv.
func ResolveTrunk(repo *gitx.Repo, getenv func(string) string) (*Trunk, error) {
	var t *Trunk
	if v := getenv(TrunkEnv); v != "" {
		if err := config.CheckTrunk(v); err != nil {
			return nil, fmt.Errorf("%s: %w", TrunkEnv, err)
		}
		t = &Trunk{Name: v, From: TrunkFromEnv}
	} else if v, ok, err := repo.ConfigGet(TrunkConfigKey); err != nil {
		return nil, err
	} else if ok {
		if err := config.CheckTrunk(v); err != nil {
			return nil, fmt.Errorf("git config %s: %w", TrunkConfigKey, err)
		}
		t = &Trunk{Name: v, From: TrunkFromGitConfig}
	} else {
		def, ok, err := repo.RemoteDefault()
		if err != nil {
			return nil, err
		}
		if !ok {
			remotes, err := repo.HasRemoteRefs()
			if err != nil {
				return nil, err
			}
			if remotes {
				return nil, &NoTrunkError{}
			}
			return &Trunk{From: TrunkFromNone}, nil
		}
		t = &Trunk{Name: def, From: TrunkFromRemote}
	}
	if t.Name == config.TrunkWorktree {
		t.Ref = t.Name
		return t, nil
	}
	full, commit, found, err := repo.ResolveBranchRef(t.Name)
	if err != nil {
		return nil, fmt.Errorf("trunk (from %s): %w", t.From, err)
	}
	if !found {
		return nil, &TrunkMissingError{Ref: t.Name, From: t.From}
	}
	t.Ref, t.Commit = full, commit
	return t, nil
}

// LoadTrunkWith reads trunk policy using getenv for CARBON_TRUNK. See
// [LoadTrunk].
func LoadTrunkWith(repo *gitx.Repo, getenv func(string) string) (*Policy, error) {
	t, err := ResolveTrunk(repo, getenv)
	if err != nil {
		return nil, err
	}
	return LoadTrunkAt(repo, t)
}

// LoadTrunkAt reads policy for a resolved trunk:
//
//   - "worktree": the working tree (OriginWorktreeTrunk);
//   - no trunk (TrunkFromNone): the working tree (OriginBootstrap);
//   - the ref does not resolve: a *TrunkMissingError;
//   - the ref has no root carbon.toml: the working tree (OriginBootstrap);
//   - otherwise: the ref (OriginTrunk).
//
// Bootstrap sets Policy.Notice. Policy.Trunk records the resolution.
func LoadTrunkAt(repo *gitx.Repo, t *Trunk) (*Policy, error) {
	p, err := loadTrunkAt(repo, t)
	if err != nil {
		return nil, err
	}
	p.Trunk = t
	return p, nil
}

func loadTrunkAt(repo *gitx.Repo, t *Trunk) (*Policy, error) {
	if t.IsWorktree() {
		p, err := LoadWorktree(repo.Root)
		if err != nil {
			return nil, err
		}
		p.Origin = OriginWorktreeTrunk
		return p, nil
	}
	bootstrap := func(why string) (*Policy, error) {
		p, err := LoadWorktree(repo.Root)
		if err != nil {
			return nil, err
		}
		p.Origin, p.Ref = OriginBootstrap, t.Ref
		p.Notice = fmt.Sprintf("notice: %s; reading policy from the working tree until carbon is on trunk.", why)
		return p, nil
	}
	if t.From == TrunkFromNone {
		return bootstrap(fmt.Sprintf("this repository has no trunk yet (no remote and no %s)", TrunkConfigKey))
	}
	if t.Commit == "" {
		return nil, &TrunkMissingError{Ref: t.Ref, From: t.From}
	}
	src := repo.Source(t.Commit)
	if data, err := src.ReadFile(config.FileName); errors.Is(err, fs.ErrNotExist) {
		return bootstrap(fmt.Sprintf("trunk %s has no %s", t.Ref, config.FileName))
	} else if err != nil {
		return nil, err
	} else if config.IsUnadoptedRoot(data) {
		// A root file with no [workspace] (a carbon 0.0.3 service) means
		// carbon 1.0 is not adopted on trunk yet: this is the carbon-migrate
		// cutover branch. A root with [workspace] is loaded and fails closed.
		return bootstrap(fmt.Sprintf("trunk %s still has a carbon 0.0.3 %s (no [workspace])", t.Ref, config.FileName))
	}
	p, err := Load(src)
	if err != nil {
		return nil, fmt.Errorf("reading policy from trunk %s: %w", t.Ref, err)
	}
	p.Origin, p.Ref = OriginTrunk, t.Ref
	return p, nil
}
