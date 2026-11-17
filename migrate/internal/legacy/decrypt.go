package legacy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// MetaKey is the bookkeeping entry 0.0.3 writes into every registry.
const MetaKey = "_carbon"

// Values is a decrypted registry: service name -> pushed key -> value.
type Values map[string]map[string]string

// Decrypt decrypts a registry with sops and the 0.0.3 private key, the way
// `carbon view` does, and returns its values. The plaintext stays in memory;
// sops writes it to a pipe, never to disk. Non-string values (which 0.0.3
// cannot push, but a hand-edited registry could hold) are rendered as JSON.
func Decrypt(sops, root string, r *Registry, keyFile string, environ []string) (Values, error) {
	if environ == nil {
		environ = os.Environ()
	}
	args := []string{}
	if r.HasSops {
		args = append(args, "--config", filepath.Join(root, r.SopsFile))
	}
	args = append(args, "--decrypt", "--output-type", "json", filepath.Join(root, r.RegistryFile))
	cmd := exec.Command(sops, args...)
	cmd.Dir = root
	cmd.Env = append(withoutEnv(environ, "SOPS_AGE_KEY", "SOPS_AGE_KEY_FILE", "SOPS_AGE_KEY_CMD"),
		"SOPS_AGE_KEY_FILE="+keyFile)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("sops could not decrypt %s: %v\n%s", r.RegistryFile, err, indent(stderr.String()))
	}
	defer clear(stdout.Bytes())
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(stdout.Bytes(), &raw); err != nil {
		return nil, fmt.Errorf("%s: decrypted registry is not a JSON object", r.RegistryFile)
	}
	out := Values{}
	for svc, body := range raw {
		if svc == MetaKey {
			continue
		}
		var entries map[string]json.RawMessage
		if err := json.Unmarshal(body, &entries); err != nil {
			return nil, fmt.Errorf("%s: entry %q is not a mapping", r.RegistryFile, svc)
		}
		vals := map[string]string{}
		for k, v := range entries {
			var s string
			if json.Unmarshal(v, &s) == nil {
				vals[k] = s
				continue
			}
			vals[k] = strings.TrimSpace(string(v))
		}
		out[svc] = vals
	}
	return out, nil
}

// Get returns a value and whether it exists.
func (v Values) Get(service, key string) (string, bool) {
	m, ok := v[service]
	if !ok {
		return "", false
	}
	s, ok := m[key]
	return s, ok
}

func withoutEnv(env []string, names ...string) []string {
	var out []string
outer:
	for _, kv := range env {
		for _, n := range names {
			if strings.HasPrefix(kv, n+"=") {
				continue outer
			}
		}
		out = append(out, kv)
	}
	return out
}

// WithoutEnv is exported for the migrate package.
func WithoutEnv(env []string, names ...string) []string { return withoutEnv(env, names...) }

func indent(s string) string {
	s = strings.TrimRight(s, "\n")
	if s == "" {
		return ""
	}
	return "  " + strings.ReplaceAll(s, "\n", "\n  ")
}

// Quote is strconv.Quote, kept here so messages quote names consistently.
func Quote(s string) string { return strconv.Quote(s) }
