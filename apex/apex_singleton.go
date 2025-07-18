/*
 * Copyright (C) 2020 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package apex

import (
	"encoding/json"
	"strings"

	"github.com/google/blueprint"

	"android/soong/android"
)

func init() {
	registerApexDepsInfoComponents(android.InitRegistrationContext)
}

func registerApexDepsInfoComponents(ctx android.RegistrationContext) {
	ctx.RegisterParallelSingletonType("apex_depsinfo_singleton", apexDepsInfoSingletonFactory)
}

type apexDepsInfoSingleton struct {
	allowedApexDepsInfoCheckResult android.OutputPath
}

func apexDepsInfoSingletonFactory() android.Singleton {
	return &apexDepsInfoSingleton{}
}

var (
	// Generate new apex allowed_deps.txt by merging all internal dependencies.
	generateApexDepsInfoFilesRule = pctx.AndroidStaticRule("generateApexDepsInfoFilesRule", blueprint.RuleParams{
		Command: "cat $out.rsp | xargs cat" +
			// Only track non-external dependencies, i.e. those that end up in the binary
			" | grep -v '(external)'" +
			// Allowlist androidx deps
			" | grep -v '^androidx\\.'" +
			" | grep -v '^prebuilt_androidx\\.'" +
			// Ignore comments in any of the files
			" | grep -v '^#'" +
			" | sort -u -f >$out",
		Rspfile:        "$out.rsp",
		RspfileContent: "$in",
	})

	// Diff two given lists while ignoring comments in the allowed deps file.
	diffAllowedApexDepsInfoRule = pctx.AndroidStaticRule("diffAllowedApexDepsInfoRule", blueprint.RuleParams{
		Description: "Diff ${allowed_deps} and ${new_allowed_deps}",
		Command: `
			if grep -v '^#' ${allowed_deps} | diff -B - ${new_allowed_deps}; then
			   touch ${out};
			else
				echo;
				echo "******************************";
				echo "ERROR: go/apex-allowed-deps-error contains more information";
				echo "******************************";
				echo "Detected changes to allowed dependencies in updatable modules.";
				echo "To fix and update packages/modules/common/build/allowed_deps.txt, please run:";
				echo "$$ (croot && packages/modules/common/build/update-apex-allowed-deps.sh)";
				echo;
				echo "When submitting the generated CL, you must include the following information";
				echo "in the commit message if you are adding a new dependency:";
				echo "Apex-Size-Increase: Expected binary size increase for affected APEXes (or the size of the .jar / .so file of the new library)";
				echo "Previous-Platform-Support: Are the maintainers of the new dependency committed to supporting previous platform releases?";
				echo "Aosp-First: Is the new dependency being developed AOSP-first or internal?";
				echo "Test-Info: What’s the testing strategy for the new dependency? Does it have its own tests, and are you adding integration tests? How/when are the tests run?";
				echo "You do not need OWNERS approval to submit the change, but mainline-modularization@";
				echo "will periodically review additions and may require changes.";
				echo "******************************";
				echo;
				exit 1;
			fi;
		`,
	}, "allowed_deps", "new_allowed_deps")
)

func (s *apexDepsInfoSingleton) GenerateBuildActions(ctx android.SingletonContext) {
	updatableFlatLists := android.Paths{}
	ctx.VisitAllModuleProxies(func(module android.ModuleProxy) {
		if binaryInfo, ok := android.OtherModuleProvider(ctx, module, android.ApexBundleDepsDataProvider); ok {
			apexInfo, _ := android.OtherModuleProvider(ctx, module, android.ApexInfoProvider)
			if path := binaryInfo.FlatListPath; path != nil {
				if binaryInfo.Updatable || apexInfo.Updatable {
					if strings.HasPrefix(module.String(), "com.android.") {
						updatableFlatLists = append(updatableFlatLists, path)
					}
				}
			}
		}
	})

	allowedDepsSource := android.ExistentPathForSource(ctx, "packages/modules/common/build/allowed_deps.txt")
	newAllowedDeps := android.PathForOutput(ctx, "apex", "depsinfo", "new-allowed-deps.txt")
	s.allowedApexDepsInfoCheckResult = android.PathForOutput(ctx, newAllowedDeps.Rel()+".check")

	if !allowedDepsSource.Valid() {
		// Unbundled projects may not have packages/modules/common/ checked out; ignore those.
		ctx.Build(pctx, android.BuildParams{
			Rule:   android.Touch,
			Output: s.allowedApexDepsInfoCheckResult,
		})
	} else {
		allowedDeps := allowedDepsSource.Path()

		ctx.Build(pctx, android.BuildParams{
			Rule:   generateApexDepsInfoFilesRule,
			Inputs: append(updatableFlatLists, allowedDeps),
			Output: newAllowedDeps,
		})

		ctx.Build(pctx, android.BuildParams{
			Rule:   diffAllowedApexDepsInfoRule,
			Input:  newAllowedDeps,
			Output: s.allowedApexDepsInfoCheckResult,
			Args: map[string]string{
				"allowed_deps":     allowedDeps.String(),
				"new_allowed_deps": newAllowedDeps.String(),
			},
		})
	}

	ctx.Phony("apex-allowed-deps-check", s.allowedApexDepsInfoCheckResult)
}

func (s *apexDepsInfoSingleton) MakeVars(ctx android.MakeVarsContext) {
	// Export check result to Make. The path is added to droidcore.
	ctx.Strict("APEX_ALLOWED_DEPS_CHECK", s.allowedApexDepsInfoCheckResult.String())
}

func init() {
	registerApexPrebuiltInfoComponents(android.InitRegistrationContext)
}

func registerApexPrebuiltInfoComponents(ctx android.RegistrationContext) {
	ctx.RegisterParallelSingletonType("apex_prebuiltinfo_singleton", apexPrebuiltInfoFactory)
}

func apexPrebuiltInfoFactory() android.Singleton {
	return &apexPrebuiltInfo{}
}

type apexPrebuiltInfo struct {
	out android.WritablePath
}

func (a *apexPrebuiltInfo) GenerateBuildActions(ctx android.SingletonContext) {
	prebuiltInfos := []android.PrebuiltInfo{}

	ctx.VisitAllModuleProxies(func(m android.ModuleProxy) {
		prebuiltInfo, exists := android.OtherModuleProvider(ctx, m, android.PrebuiltInfoProvider)
		// Use prebuiltInfoProvider to filter out non apex soong modules.
		// Use HideFromMake to filter out the unselected variants of a specific apex.
		if exists && !android.OtherModulePointerProviderOrDefault(ctx, m, android.CommonModuleInfoProvider).HideFromMake {
			prebuiltInfos = append(prebuiltInfos, prebuiltInfo)
		}
	})

	j, err := json.Marshal(prebuiltInfos)
	if err != nil {
		ctx.Errorf("Could not convert prebuilt info of apexes to json due to error: %v", err)
	}
	a.out = android.PathForOutput(ctx, "prebuilt_info.json")
	android.WriteFileRule(ctx, a.out, string(j))
	ctx.DistForGoal("droidcore", a.out)
}
