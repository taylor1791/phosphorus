package config

import (
	"errors"
	"fmt"
	"path"
	"strings"

	"github.com/taylor1791/phosphorus/internal/agewrap"
)

// Person is .carbon/people/<id>.toml.
type Person struct {
	ID      string            // the file's base name
	Name    string            // display name, optional
	Devices map[string]string // device name -> recipient
}

// Machine is .carbon/machines/<id>.toml.
type Machine struct {
	ID          string
	Description string
	Key         string // recipient
}

// Teams is .carbon/teams.toml: team name -> person ids.
type Teams map[string][]string

type personTOML struct {
	Name    string            `toml:"name"`
	Devices map[string]string `toml:"devices"`
}

type machineTOML struct {
	Description string `toml:"description"`
	Key         string `toml:"key"`
}

// ParsePerson parses a person file. id is the file's base name.
func ParsePerson(file, id string, data []byte) (*Person, error) {
	if HasConflictMarkers(data) {
		return nil, &ConflictError{Path: file}
	}
	if err := CheckName("person", id); err != nil {
		return nil, &FileError{file, err}
	}
	var t personTOML
	if err := strictDecode(data, &t); err != nil {
		return nil, &FileError{file, err}
	}
	p := &Person{ID: id, Name: t.Name, Devices: t.Devices}
	if p.Devices == nil {
		p.Devices = map[string]string{}
	}
	for dev, rec := range p.Devices {
		if err := CheckName("device", dev); err != nil {
			return nil, &FileError{file, err}
		}
		if err := checkRecipient(rec); err != nil {
			return nil, &FileError{file, fmt.Errorf("device %s: %w", dev, err)}
		}
	}
	return p, nil
}

// ParseMachine parses a machine file. id is the file's base name.
func ParseMachine(file, id string, data []byte) (*Machine, error) {
	if HasConflictMarkers(data) {
		return nil, &ConflictError{Path: file}
	}
	if err := CheckName("machine", id); err != nil {
		return nil, &FileError{file, err}
	}
	var t machineTOML
	if err := strictDecode(data, &t); err != nil {
		return nil, &FileError{file, err}
	}
	if t.Key == "" {
		return nil, &FileError{file, errors.New(`a machine needs key = "<age recipient>"`)}
	}
	if err := checkRecipient(t.Key); err != nil {
		return nil, &FileError{file, err}
	}
	return &Machine{ID: id, Description: t.Description, Key: t.Key}, nil
}

// ParseTeams parses the teams file.
func ParseTeams(file string, data []byte) (Teams, error) {
	if HasConflictMarkers(data) {
		return nil, &ConflictError{Path: file}
	}
	var t map[string][]string
	if err := strictDecode(data, &t); err != nil {
		return nil, &FileError{file, err}
	}
	teams := Teams{}
	for name, members := range t {
		if err := CheckName("team", name); err != nil {
			return nil, &FileError{file, err}
		}
		for _, m := range members {
			if err := CheckName("person", m); err != nil {
				return nil, &FileError{file, fmt.Errorf("team %s: %w (teams list people only)", name, err)}
			}
		}
		teams[name] = members
	}
	return teams, nil
}

func checkRecipient(rec string) error {
	if agewrap.RecipientKind(rec) == "" {
		return fmt.Errorf("%q is not an age recipient", rec)
	}
	return nil
}

// MarshalPerson writes a person file deterministically.
func MarshalPerson(p *Person) []byte {
	var b strings.Builder
	if p.Name != "" {
		fmt.Fprintf(&b, "name = %s\n\n", Quote(p.Name))
	}
	b.WriteString("[devices]\n")
	for _, d := range sortedKeys(p.Devices) {
		fmt.Fprintf(&b, "%s = %s\n", d, Quote(p.Devices[d]))
	}
	return []byte(b.String())
}

// MarshalMachine writes a machine file deterministically.
func MarshalMachine(m *Machine) []byte {
	var b strings.Builder
	if m.Description != "" {
		fmt.Fprintf(&b, "description = %s\n", Quote(m.Description))
	}
	fmt.Fprintf(&b, "key = %s\n", Quote(m.Key))
	return []byte(b.String())
}

// MarshalTeams writes the teams file deterministically.
func MarshalTeams(t Teams) []byte {
	var b strings.Builder
	for _, name := range sortedKeys(t) {
		q := make([]string, len(t[name]))
		for i, m := range t[name] {
			q[i] = Quote(m)
		}
		fmt.Fprintf(&b, "%s = [%s]\n", name, strings.Join(q, ", "))
	}
	return []byte(b.String())
}

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

// PersonFile is the path of a person's file.
func PersonFile(id string) string { return path.Join(PeopleDir, id+".toml") }

// MachineFile is the path of a machine's file.
func MachineFile(id string) string { return path.Join(MachinesDir, id+".toml") }
