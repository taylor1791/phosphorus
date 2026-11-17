package config

import (
	"errors"
	"fmt"
	"io/fs"
	"path"
	"strings"
)

// LoadWorkspace reads the root carbon.toml from src. It returns an error
// wrapping fs.ErrNotExist if there is none, and an error if the root file
// has no [workspace] table.
func LoadWorkspace(src Source) (*Workspace, error) {
	data, err := src.ReadFile(FileName)
	if err != nil {
		return nil, err
	}
	ws, _, err := ParseFile(FileName, data)
	if err != nil {
		return nil, err
	}
	if ws == nil {
		return nil, &FileError{FileName, errors.New("the root carbon.toml has no [workspace] table")}
	}
	return ws, nil
}

// LoadPackages finds and parses every package in src, including the root
// file when it has a name. Package names must be unique.
func LoadPackages(src Source, ws *Workspace) (map[string]*Package, error) {
	files, err := src.Find(FileName)
	if err != nil {
		return nil, err
	}
	pkgs := map[string]*Package{}
	for _, f := range files {
		data, err := src.ReadFile(f)
		if err != nil {
			return nil, err
		}
		fws, p, err := ParseFile(f, data)
		if err != nil {
			return nil, err
		}
		if fws != nil && f != FileName {
			return nil, &FileError{f, errors.New("only the root carbon.toml may have a [workspace] table")}
		}
		if p == nil {
			continue
		}
		if err := ws.ValidatePackage(p); err != nil {
			return nil, &FileError{f, err}
		}
		if prev, ok := pkgs[p.Name]; ok {
			return nil, &FileError{f, fmt.Errorf("package name %q is also used by %s", p.Name, prev.File)}
		}
		pkgs[p.Name] = p
	}
	return pkgs, nil
}

// LoadPeople reads .carbon/people/*.toml.
func LoadPeople(src Source) (map[string]*Person, error) {
	out := map[string]*Person{}
	err := eachTOML(src, PeopleDir, func(file, id string, data []byte) error {
		p, err := ParsePerson(file, id, data)
		if err == nil {
			out[id] = p
		}
		return err
	})
	return out, err
}

// LoadMachines reads .carbon/machines/*.toml.
func LoadMachines(src Source) (map[string]*Machine, error) {
	out := map[string]*Machine{}
	err := eachTOML(src, MachinesDir, func(file, id string, data []byte) error {
		m, err := ParseMachine(file, id, data)
		if err == nil {
			out[id] = m
		}
		return err
	})
	return out, err
}

// LoadTeams reads .carbon/teams.toml; a missing file means no teams.
func LoadTeams(src Source) (Teams, error) {
	data, err := readIfExists(src, TeamsFile)
	if err != nil {
		return nil, err
	}
	if data == nil {
		return Teams{}, nil
	}
	return ParseTeams(TeamsFile, data)
}

func eachTOML(src Source, dir string, fn func(file, id string, data []byte) error) error {
	names, err := src.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, n := range names {
		id, ok := strings.CutSuffix(n, ".toml")
		if !ok {
			continue
		}
		file := path.Join(dir, n)
		data, err := src.ReadFile(file)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		if err := fn(file, id, data); err != nil {
			return err
		}
	}
	return nil
}
