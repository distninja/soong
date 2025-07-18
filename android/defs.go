// Copyright 2015 Google Inc. All rights reserved.
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

package android

import (
	"github.com/google/blueprint"
)

var (
	pctx = NewPackageContext("android/soong/android")

	cpPreserveSymlinks = pctx.VariableConfigMethod("cpPreserveSymlinks",
		Config.CpPreserveSymlinksFlags)

	// A phony rule that is not the built-in Ninja phony rule.  The built-in
	// phony rule has special behavior that is sometimes not desired.  See the
	// Ninja docs for more details.
	Phony = pctx.AndroidStaticRule("Phony",
		blueprint.RuleParams{
			Command:     "# phony $out",
			Description: "phony $out",
		})

	// GeneratedFile is a rule for indicating that a given file was generated
	// while running soong.  This allows the file to be cleaned up if it ever
	// stops being generated by soong.
	GeneratedFile = pctx.AndroidStaticRule("GeneratedFile",
		blueprint.RuleParams{
			Command:     "# generated $out",
			Description: "generated $out",
			Generator:   true,
		})

	// A copy rule.
	Cp = pctx.AndroidStaticRule("Cp",
		blueprint.RuleParams{
			Command:     "rm -f $out && cp $cpPreserveSymlinks $cpFlags $in $out$extraCmds",
			Description: "cp $out",
		},
		"cpFlags", "extraCmds")

	// A copy rule wrapped with bash.
	CpWithBash = pctx.AndroidStaticRule("CpWithBash",
		blueprint.RuleParams{
			Command:     "/bin/bash -c \"rm -f $out && cp $cpFlags $cpPreserveSymlinks $in $out$extraCmds\"",
			Description: "cp $out",
		},
		"cpFlags", "extraCmds")

	// A copy rule that doesn't preserve symlinks.
	CpNoPreserveSymlink = pctx.AndroidStaticRule("CpNoPreserveSymlink",
		blueprint.RuleParams{
			Command:     "rm -f $out && cp $cpFlags $in $out$extraCmds",
			Description: "cp $out",
		},
		"cpFlags", "extraCmds")

	// A copy rule that only updates the output if it changed.
	CpIfChanged = pctx.AndroidStaticRule("CpIfChanged",
		blueprint.RuleParams{
			Command:     "if ! cmp -s $in $out; then cp $in $out; fi",
			Description: "cp if changed $out",
			Restat:      true,
		})

	CpExecutable = pctx.AndroidStaticRule("CpExecutable",
		blueprint.RuleParams{
			Command:     "rm -f $out && cp $cpFlags $in $out && chmod +x $out$extraCmds",
			Description: "cp $out",
		},
		"cpFlags", "extraCmds")

	// A copy executable rule wrapped with bash
	CpExecutableWithBash = pctx.AndroidStaticRule("CpExecutableWithBash",
		blueprint.RuleParams{
			Command:     "/bin/bash -c \"(rm -f $out && cp $cpFlags $cpPreserveSymlinks $in $out ) && (chmod +x $out$extraCmds )\"",
			Description: "cp $out",
		},
		"cpFlags", "extraCmds")

	// A timestamp touch rule.
	Touch = pctx.AndroidStaticRule("Touch",
		blueprint.RuleParams{
			Command:     "touch $out",
			Description: "touch $out",
		})

	// A symlink rule.
	Symlink = pctx.AndroidStaticRule("Symlink",
		blueprint.RuleParams{
			Command:     "rm -f $out && ln -f -s $fromPath $out",
			Description: "symlink $out",
		},
		"fromPath")

	// A symlink rule wrapped with bash
	SymlinkWithBash = pctx.AndroidStaticRule("SymlinkWithBash",
		blueprint.RuleParams{
			Command:     "/bin/bash -c \"rm -f $out && ln -sfn $fromPath $out\"",
			Description: "symlink $out",
		},
		"fromPath")

	ErrorRule = pctx.AndroidStaticRule("Error",
		blueprint.RuleParams{
			Command:     `echo "$error" && false`,
			Description: "error building $out",
		},
		"error")

	Cat = pctx.AndroidStaticRule("Cat",
		blueprint.RuleParams{
			Command:     "rm -f $out && cat $in > $out",
			Description: "concatenate files to $out",
		})

	CatAndSort = pctx.AndroidStaticRule("CatAndSort",
		blueprint.RuleParams{
			Command:     "rm -f $out && cat $in > $out && sort -o $out $out",
			Description: "concatenate sorted file contents to $out",
		})

	// Used only when USE_GOMA=true is set, to restrict non-goma jobs to the local parallelism value
	localPool = blueprint.NewBuiltinPool("local_pool")

	// Used only by RuleBuilder to identify remoteable rules. Does not actually get created in ninja.
	remotePool = blueprint.NewBuiltinPool("remote_pool")

	// Used for processes that need significant RAM to ensure there are not too many running in parallel.
	highmemPool = blueprint.NewBuiltinPool("highmem_pool")
)

func init() {
	pctx.Import("github.com/google/blueprint/bootstrap")

	pctx.VariableFunc("RBEWrapper", func(ctx PackageVarContext) string {
		return ctx.Config().RBEWrapper()
	})
}

// CopyFileRule creates a ninja rule to copy path to outPath.
func CopyFileRule(ctx ModuleContext, path Path, outPath OutputPath) {
	ctx.Build(pctx, BuildParams{
		Rule:        Cp,
		Input:       path,
		Output:      outPath,
		Description: "copy " + outPath.Base(),
	})
}
