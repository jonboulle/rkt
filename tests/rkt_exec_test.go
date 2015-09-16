// Copyright 2015 The rkt Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"fmt"
	"os"
	"testing"

	"github.com/coreos/rkt/Godeps/_workspace/src/github.com/steveeJ/gexpect"
)

func TestRunOverrideExec(t *testing.T) {
	execImage := patchTestACI("rkt-exec-override.aci", "--exec=/inspect")
	defer os.Remove(execImage)
	ctx := newRktRunCtx()
	defer ctx.cleanup()

	for _, tt := range []struct {
		rktCmd       string
		expectedLine string
	}{
		{
			// Sanity check - make sure no --exec override prints the expected exec invocation
			rktCmd:       fmt.Sprintf("%s --insecure-skip-verify run --mds-register=false %s -- --print-exec", ctx.cmd(), execImage),
			expectedLine: "inspect execed as: /inspect",
		},
		{
			// Now test overriding the entrypoint (which is a symlink to /inspect so should behave identically)
			rktCmd:       fmt.Sprintf("%s --insecure-skip-verify run --mds-register=false %s --exec /inspect-link -- --print-exec", ctx.cmd(), execImage),
			expectedLine: "inspect execed as: /inspect-link",
		},
	} {
		runRktAndChkOutput(t, tt.rktCmd, tt.expectedLine)
	}
}

func TestRunPreparedExec(t *testing.T) {
	execImage := patchTestACI("rkt-exec-override.aci", "--exec=/inspect")
	defer os.Remove(execImage)
	ctx := newRktRunCtx()
	defer ctx.cleanup()

	var rktCmd, uuid, expected string

	// Sanity check - make sure no --exec override prints the expected exec invocation
	rktCmd = fmt.Sprintf("%s prepare --insecure-skip-verify %s -- --print-exec", ctx.cmd(), execImage)
	uuid = runRktAndGetLastLine(t, rktCmd)

	t.Logf("Prepared rkt container has uuid: %s", uuid)

	rktCmd = fmt.Sprintf("%s run-prepared %s", ctx.cmd(), uuid)
	expected = "inspect execed as: /inspect"
	runRktAndChkOutput(t, rktCmd, expected)

	// Now test overriding the entrypoint (which is a symlink to /inspect so should behave identically)
	rktCmd = fmt.Sprintf("%s prepare --insecure-skip-verify %s --exec /inspect-link -- --print-exec", ctx.cmd(), execImage)
	uuid = runRktAndGetLastLine(t, rktCmd)

	t.Logf("Prepared rkt container has uuid: %s", uuid)

	rktCmd = fmt.Sprintf("%s run-prepared --mds-register=false %s", ctx.cmd(), uuid)
	expected = "inspect execed as: /inspect-link"
	runRktAndChkOutput(t, rktCmd, expected)
}

func runRktAndChkOutput(t *testing.T, rktCmd, expectedLine string) {
	t.Logf("rkt: %s", rktCmd)
	child, err := gexpect.Spawn(rktCmd)
	if err != nil {
		t.Fatalf("cannot exec rkt: %v", err)
	}

	if err = expectWithOutput(child, expectedLine); err != nil {
		t.Fatalf("didn't receive expected output %q: %v", expectedLine, err)
	}

	if err = child.Wait(); err != nil {
		t.Fatalf("rkt didn't terminate correctly: %v", err)
	}
}

func runRktAndGetLastLine(t *testing.T, rktCmd string) string {
	t.Logf("rkt: %s", rktCmd)
	child, err := gexpect.Spawn(rktCmd)
	if err != nil {
		t.Fatalf("cannot exec rkt: %v", err)
	}

	// To get the last line, keep reading lines until an error is returned
	var l, line string
	for {
		l, err = child.ReadLine()
		if err == nil {
			line = l
		} else {
			break
		}
	}

	if err = child.Wait(); err != nil {
		t.Fatalf("rkt didn't terminate correctly (got \"%s\"): %v", line, err)
	}
	return line
}
