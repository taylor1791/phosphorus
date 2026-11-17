// Command childhelper is a stand-in program for carbon's CLI tests: the
// command `carbon run` executes and the editor `carbon edit` opens.
//
//	childhelper env [code]   print {"args": [...], "env": [...]} as JSON, exit code
//	childhelper exit         exit 0 at once (for timing)
//	childhelper edit <file>  act as an editor, driven by HELPER_EDIT_* variables:
//	    HELPER_EDIT_LOG     append "path mode dirmode identity-vars=<bool>" to this file
//	    HELPER_EDIT_SET     JSON {"name": "value"}: replace or uncomment that line
//	    HELPER_EDIT_APPEND  text appended to the file
//	    HELPER_EDIT_EXIT    exit with this status after editing
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

func main() {
	if len(os.Args) < 2 {
		os.Exit(2)
	}
	switch os.Args[1] {
	case "exit":
		os.Exit(0)
	case "env":
		env := os.Environ()
		sort.Strings(env)
		json.NewEncoder(os.Stdout).Encode(map[string][]string{"args": os.Args, "env": env})
		code := 0
		if len(os.Args) > 2 {
			code, _ = strconv.Atoi(os.Args[2])
		}
		os.Exit(code)
	case "edit":
		edit(os.Args[len(os.Args)-1])
	default:
		os.Exit(2)
	}
}

func edit(path string) {
	if log := os.Getenv("HELPER_EDIT_LOG"); log != "" {
		fi, err := os.Stat(path)
		di, err2 := os.Stat(filepath.Dir(path))
		if err != nil || err2 != nil {
			os.Exit(9)
		}
		f, _ := os.OpenFile(log, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		_, id := os.LookupEnv("CARBON_IDENTITY")
		_, idf := os.LookupEnv("CARBON_IDENTITY_FILE")
		fmt.Fprintf(f, "%s %04o %04o identity-vars=%v\n", path, fi.Mode().Perm(), di.Mode().Perm(), id || idf)
		f.Close()
	}
	data, err := os.ReadFile(path)
	if err != nil {
		os.Exit(9)
	}
	lines := strings.Split(string(data), "\n")
	if set := os.Getenv("HELPER_EDIT_SET"); set != "" {
		var m map[string]string
		if err := json.Unmarshal([]byte(set), &m); err != nil {
			os.Exit(9)
		}
		for name, v := range m {
			q, _ := json.Marshal(v) // a JSON string is a valid TOML basic string for these tests
			found := false
			for i, l := range lines {
				if strings.HasPrefix(l, name+" = ") || strings.HasPrefix(l, "# "+name+" = ") {
					lines[i] = name + " = " + string(q)
					found = true
				}
			}
			if !found {
				lines = append(lines, name+" = "+string(q))
			}
		}
	}
	out := strings.Join(lines, "\n") + os.Getenv("HELPER_EDIT_APPEND")
	if err := os.WriteFile(path, []byte(out), 0o600); err != nil {
		os.Exit(9)
	}
	// Leave an editor-style backup file next to it, as vim would.
	os.WriteFile(path+"~", data, 0o600)
	if c := os.Getenv("HELPER_EDIT_EXIT"); c != "" {
		n, _ := strconv.Atoi(c)
		os.Exit(n)
	}
}
