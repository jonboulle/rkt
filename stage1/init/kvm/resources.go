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

package kvm

import (
	"fmt"
	"runtime"

	"github.com/coreos/rkt/Godeps/_workspace/src/github.com/appc/spec/schema"
	"github.com/coreos/rkt/Godeps/_workspace/src/github.com/appc/spec/schema/types"
)

const (
	defaultMem        = 128 // MB
	systemMemOverhead = 128 // MB
)

// findResources finds value of last isolator for particular type.
func findResources(isolators types.Isolators) (mem, cpus int64) {
	fmt.Printf("%#v\n", isolators)
	mem = defaultMem
	for _, i := range isolators {
		switch v := i.Value().(type) {
		case *types.ResourceMemory:
			mem = v.Limit().Value()
			// Convert bytes into megabytes
			mem /= 1024 * 1024
		case *types.ResourceCPU:
			cpus = v.Limit().Value()
		}
	}
	return mem, cpus
}

// GetAppsResources returns the values for apps' resource limits specified in
// an AppList (from a PodManifest). It returns the aggregate quantity of memory
// (in MB) and CPUs. If resource limits are not found in the AppList, default values
// are used.
func GetAppsResources(apps schema.AppList) (totalCpus, totalMem int64) {
	cpusSpecified := true
	for i := range apps {
		ra := &apps[i]
		app := ra.App
		mem, cpus := findResources(app.Isolators)
		cpusSpecified = cpusSpecified && cpus != 0
		totalCpus += cpus
		totalMem += mem
	}
	// If user doesn't specify CPUs for any app, we set no limit for whole
	// pod.
	if !cpusSpecified {
		totalCpus = int64(runtime.NumCPU())
	}

	// Add an overhead for the VM system
	totalMem += systemMemOverhead

	return totalCpus, totalMem
}
