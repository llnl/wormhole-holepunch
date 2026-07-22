package tools

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

/*
	Our list of malicious strings is built heavily relying upon upon OpenSource projects:

	* Big List of Naughty Strings
		License: https://github.com/minimaxir/big-list-of-naughty-strings/blob/master/LICENSE
		Copyright (c) 2015-2020 Max Woolf

	Please note we've had to removed a number of elements from the original lists
	as they were unrelated to our target scenarios and presented issues with integrating
	into our testing strategies.
*/

var unencoded []string

func init() {
	unencoded = load()
}

// UnencodedFuzzStr returns a list of (near) universally disallowed strings by all
// currently established rules.
func UnencodedFuzzStr() []string {
	return unencoded
}

func load() []string {
	_, file, _, _ := runtime.Caller(0)

	b, err := os.ReadFile(filepath.Clean(strings.ReplaceAll(file, "fuzz.go", "mal.json")))
	if err != nil {
		panic(err)
	}

	var s []string
	if err := json.Unmarshal(b, &s); err != nil {
		panic(err)
	}

	return s
}
