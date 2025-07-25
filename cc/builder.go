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

package cc

// This file generates the final rules for compiling all C/C++.  All properties related to
// compiling should have been translated into builderFlags or another argument to the Transform*
// functions.

import (
	"fmt"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"

	"github.com/google/blueprint"
	"github.com/google/blueprint/pathtools"

	"android/soong/android"
	"android/soong/cc/config"
	"android/soong/remoteexec"
)

const (
	objectExtension        = ".o"
	staticLibraryExtension = ".a"
)

var (
	pctx = android.NewPackageContext("android/soong/cc")

	// Rule to invoke gcc with given command, flags, and dependencies. Outputs a .d depfile.
	cc = pctx.AndroidRemoteStaticRule("cc", android.RemoteRuleSupports{Goma: true, RBE: true},
		blueprint.RuleParams{
			Depfile:     "${out}.d",
			Deps:        blueprint.DepsGCC,
			Command:     "$relPwd ${config.CcWrapper}$ccCmd -c $cFlags -MD -MF ${out}.d -o $out $in$postCmd",
			CommandDeps: []string{"$ccCmd"},
		},
		"ccCmd", "cFlags", "postCmd")

	// Rule to invoke gcc with given command and flags, but no dependencies.
	ccNoDeps = pctx.AndroidStaticRule("ccNoDeps",
		blueprint.RuleParams{
			Command:     "$relPwd $ccCmd -c $cFlags -o $out $in$postCmd",
			CommandDeps: []string{"$ccCmd"},
		},
		"ccCmd", "cFlags", "postCmd")

	// Rules to invoke ld to link binaries. Uses a .rsp file to list dependencies, as there may
	// be many.
	ld, ldRE = pctx.RemoteStaticRules("ld",
		blueprint.RuleParams{
			Command: "$reTemplate$ldCmd ${crtBegin} @${out}.rsp " +
				"${crtEnd} -o ${out} ${ldFlags} ${extraLibFlags}",
			CommandDeps:    []string{"$ldCmd"},
			Rspfile:        "${out}.rsp",
			RspfileContent: "${in} ${libFlags}",
			// clang -Wl,--out-implib doesn't update its output file if it hasn't changed.
			Restat: true,
		},
		&remoteexec.REParams{
			Labels:          map[string]string{"type": "link", "tool": "clang"},
			ExecStrategy:    "${config.RECXXLinksExecStrategy}",
			Inputs:          []string{"${out}.rsp", "$implicitInputs"},
			RSPFiles:        []string{"${out}.rsp"},
			OutputFiles:     []string{"${out}", "$implicitOutputs"},
			ToolchainInputs: []string{"$ldCmd"},
			Platform:        map[string]string{remoteexec.PoolKey: "${config.RECXXLinksPool}"},
		}, []string{"ldCmd", "crtBegin", "libFlags", "crtEnd", "ldFlags", "extraLibFlags"}, []string{"implicitInputs", "implicitOutputs"})

	// Rules for .o files to combine to other .o files, using ld partial linking.
	partialLd, partialLdRE = pctx.RemoteStaticRules("partialLd",
		blueprint.RuleParams{
			// Without -no-pie, clang 7.0 adds -pie to link Android files,
			// but -r and -pie cannot be used together.
			Command:     "$reTemplate$ldCmd -fuse-ld=lld -nostdlib -no-pie -Wl,-r ${in} -o ${out} ${ldFlags}",
			CommandDeps: []string{"$ldCmd"},
		}, &remoteexec.REParams{
			Labels:          map[string]string{"type": "link", "tool": "clang"},
			ExecStrategy:    "${config.RECXXLinksExecStrategy}",
			Inputs:          []string{"$inCommaList", "$implicitInputs"},
			OutputFiles:     []string{"${out}", "$implicitOutputs"},
			ToolchainInputs: []string{"$ldCmd"},
			Platform:        map[string]string{remoteexec.PoolKey: "${config.RECXXLinksPool}"},
		}, []string{"ldCmd", "ldFlags"}, []string{"implicitInputs", "inCommaList", "implicitOutputs"})

	// Rule to invoke `ar` with given cmd and flags, but no static library depenencies.
	ar = pctx.AndroidStaticRule("ar",
		blueprint.RuleParams{
			Command:        "rm -f ${out} && $arCmd $arFlags $out @${out}.rsp",
			CommandDeps:    []string{"$arCmd"},
			Rspfile:        "${out}.rsp",
			RspfileContent: "${in}",
		},
		"arCmd", "arFlags")

	// Rule to invoke `ar` with given cmd, flags, and library dependencies. Generates a .a
	// (archive) file from .o files.
	arWithLibs = pctx.AndroidStaticRule("arWithLibs",
		blueprint.RuleParams{
			Command:        "rm -f ${out} && $arCmd $arObjFlags $out @${out}.rsp && $arCmd $arLibFlags $out $arLibs",
			CommandDeps:    []string{"$arCmd"},
			Rspfile:        "${out}.rsp",
			RspfileContent: "${arObjs}",
		},
		"arCmd", "arObjFlags", "arObjs", "arLibFlags", "arLibs")

	// Rule to run objcopy --prefix-symbols (to prefix all symbols in a file with a given string).
	prefixSymbols = pctx.AndroidStaticRule("prefixSymbols",
		blueprint.RuleParams{
			Command:     "$objcopyCmd --prefix-symbols=${prefix} ${in} ${out}",
			CommandDeps: []string{"$objcopyCmd"},
		},
		"objcopyCmd", "prefix")

	// Rule to run objcopy --remove-section=.llvm_addrsig on a partially linked object
	noAddrSig = pctx.AndroidStaticRule("noAddrSig",
		blueprint.RuleParams{
			Command:     "rm -f ${out} && $objcopyCmd --remove-section=.llvm_addrsig ${in} ${out}",
			CommandDeps: []string{"$objcopyCmd"},
		},
		"objcopyCmd")

	_ = pctx.SourcePathVariable("stripPath", "build/soong/scripts/strip.sh")
	_ = pctx.SourcePathVariable("xzCmd", "prebuilts/build-tools/${config.HostPrebuiltTag}/bin/xz")
	_ = pctx.SourcePathVariable("createMiniDebugInfo", "prebuilts/build-tools/${config.HostPrebuiltTag}/bin/create_minidebuginfo")

	// Rule to invoke `strip` (to discard symbols and data from object files).
	strip = pctx.AndroidStaticRule("strip",
		blueprint.RuleParams{
			Depfile: "${out}.d",
			Deps:    blueprint.DepsGCC,
			Command: "XZ=$xzCmd CREATE_MINIDEBUGINFO=$createMiniDebugInfo CLANG_BIN=${config.ClangBin} $stripPath ${args} -i ${in} -o ${out} -d ${out}.d",
			CommandDeps: func() []string {
				if runtime.GOOS != "darwin" {
					return []string{"$stripPath", "$xzCmd", "$createMiniDebugInfo"}
				} else {
					return []string{"$stripPath", "$xzCmd"}
				}
			}(),
			Pool: darwinStripPool,
		},
		"args")

	// Rule to invoke `strip` (to discard symbols and data from object files) on darwin architecture.
	darwinStrip = func() blueprint.Rule {
		if runtime.GOOS == "darwin" {
			return pctx.AndroidStaticRule("darwinStrip",
				blueprint.RuleParams{
					Command:     "${config.MacStripPath} -u -r -o $out $in",
					CommandDeps: []string{"${config.MacStripPath}"},
				})
		} else {
			return nil
		}
	}()

	// b/132822437: objcopy uses a file descriptor per .o file when called on .a files, which runs the system out of
	// file descriptors on darwin.  Limit concurrent calls to 5 on darwin.
	darwinStripPool = func() blueprint.Pool {
		if runtime.GOOS == "darwin" {
			return pctx.StaticPool("darwinStripPool", blueprint.PoolParams{
				Depth: 5,
			})
		} else {
			return nil
		}
	}()

	darwinLipo = func() blueprint.Rule {
		if runtime.GOOS == "darwin" {
			return pctx.AndroidStaticRule("darwinLipo",
				blueprint.RuleParams{
					Command:     "${config.MacLipoPath} -create -output $out $in",
					CommandDeps: []string{"${config.MacLipoPath}"},
				})
		} else {
			return nil
		}
	}()

	_ = pctx.SourcePathVariable("archiveRepackPath", "build/soong/scripts/archive_repack.sh")

	// Rule to repack an archive (.a) file with a subset of object files.
	archiveRepack = pctx.AndroidStaticRule("archiveRepack",
		blueprint.RuleParams{
			Depfile:     "${out}.d",
			Deps:        blueprint.DepsGCC,
			Command:     "CLANG_BIN=${config.ClangBin} $archiveRepackPath -i ${in} -o ${out} -d ${out}.d ${objects}",
			CommandDeps: []string{"$archiveRepackPath"},
		},
		"objects")

	// Rule to create an empty file at a given path.
	emptyFile = pctx.AndroidStaticRule("emptyFile",
		blueprint.RuleParams{
			Command: "rm -f $out && touch $out",
		})

	_ = pctx.SourcePathVariable("tocPath", "build/soong/scripts/toc.sh")

	// A rule for extracting a table of contents from a shared library (.so).
	toc = pctx.AndroidStaticRule("toc",
		blueprint.RuleParams{
			Depfile:     "${out}.d",
			Deps:        blueprint.DepsGCC,
			Command:     "CLANG_BIN=$clangBin $tocPath $format -i ${in} -o ${out} -d ${out}.d",
			CommandDeps: []string{"$tocPath"},
			Restat:      true,
		},
		"clangBin", "format")

	// Rules for invoking clang-tidy (a clang-based linter).
	clangTidy, clangTidyRE = pctx.RemoteStaticRules("clangTidy",
		blueprint.RuleParams{
			Depfile: "${out}.d",
			Deps:    blueprint.DepsGCC,
			Command: "CLANG_CMD=$clangCmd TIDY_FILE=$out " +
				"$tidyVars$reTemplate${config.ClangBin}/clang-tidy.sh $in $tidyFlags -- $cFlags",
			CommandDeps: []string{"${config.ClangBin}/clang-tidy.sh", "$ccCmd", "$tidyCmd"},
		},
		&remoteexec.REParams{
			Labels:               map[string]string{"type": "lint", "tool": "clang-tidy", "lang": "cpp"},
			ExecStrategy:         "${config.REClangTidyExecStrategy}",
			Inputs:               []string{"$in"},
			OutputFiles:          []string{"${out}", "${out}.d"},
			ToolchainInputs:      []string{"$ccCmd", "$tidyCmd"},
			EnvironmentVariables: []string{"CLANG_CMD", "TIDY_FILE", "TIDY_TIMEOUT"},
			// Although clang-tidy has an option to "fix" source files, that feature is hardly useable
			// under parallel compilation and RBE. So we assume no OutputFiles here.
			// The clang-tidy fix option is best run locally in single thread.
			// Copying source file back to local caused two problems:
			// (1) New timestamps trigger clang and clang-tidy compilations again.
			// (2) Changing source files caused concurrent clang or clang-tidy jobs to crash.
			Platform: map[string]string{remoteexec.PoolKey: "${config.REClangTidyPool}"},
		}, []string{"cFlags", "ccCmd", "clangCmd", "tidyCmd", "tidyFlags", "tidyVars"}, []string{})

	_ = pctx.SourcePathVariable("yasmCmd", "prebuilts/misc/${config.HostPrebuiltTag}/yasm/yasm")

	// Rule for invoking yasm to compile .asm assembly files.
	yasm = pctx.AndroidStaticRule("yasm",
		blueprint.RuleParams{
			Command:     "$yasmCmd $asFlags -o $out $in && $yasmCmd $asFlags -M $in >$out.d",
			CommandDeps: []string{"$yasmCmd"},
			Depfile:     "$out.d",
			Deps:        blueprint.DepsGCC,
		},
		"asFlags")

	_ = pctx.SourcePathVariable("sAbiDumper", "prebuilts/clang-tools/${config.HostPrebuiltTag}/bin/header-abi-dumper")

	// -w has been added since header-abi-dumper does not need to produce any sort of diagnostic information.
	sAbiDump, sAbiDumpRE = pctx.RemoteStaticRules("sAbiDump",
		blueprint.RuleParams{
			Command:     "rm -f $out && $reTemplate$sAbiDumper --root-dir . --root-dir $$OUT_DIR:out -o ${out} $in $exportDirs -- $cFlags -w -isystem prebuilts/clang-tools/${config.HostPrebuiltTag}/clang-headers",
			CommandDeps: []string{"$sAbiDumper"},
		}, &remoteexec.REParams{
			Labels:       map[string]string{"type": "abi-dump", "tool": "header-abi-dumper"},
			ExecStrategy: "${config.REAbiDumperExecStrategy}",
			Inputs:       []string{"$sAbiLinkerLibs"},
			Platform: map[string]string{
				remoteexec.PoolKey: "${config.RECXXPool}",
			},
		}, []string{"cFlags", "exportDirs"}, nil)

	_ = pctx.SourcePathVariable("sAbiLinker", "prebuilts/clang-tools/${config.HostPrebuiltTag}/bin/header-abi-linker")
	_ = pctx.SourcePathVariable("sAbiLinkerLibs", "prebuilts/clang-tools/${config.HostPrebuiltTag}/lib64")

	// Rule to combine .dump sAbi dump files from multiple source files into a single .ldump
	// sAbi dump file.
	sAbiLink, sAbiLinkRE = pctx.RemoteStaticRules("sAbiLink",
		blueprint.RuleParams{
			Command:        "$reTemplate$sAbiLinker --root-dir . --root-dir $$OUT_DIR:out -o ${out} $symbolFilter -arch $arch $exportedHeaderFlags @${out}.rsp",
			CommandDeps:    []string{"$sAbiLinker"},
			Rspfile:        "${out}.rsp",
			RspfileContent: "${in}",
		}, &remoteexec.REParams{
			Labels:          map[string]string{"type": "tool", "name": "abi-linker"},
			ExecStrategy:    "${config.REAbiLinkerExecStrategy}",
			Inputs:          []string{"$sAbiLinkerLibs", "${out}.rsp", "$implicitInputs"},
			RSPFiles:        []string{"${out}.rsp"},
			OutputFiles:     []string{"$out"},
			ToolchainInputs: []string{"$sAbiLinker"},
			Platform:        map[string]string{remoteexec.PoolKey: "${config.RECXXPool}"},
		}, []string{"symbolFilter", "arch", "exportedHeaderFlags"}, []string{"implicitInputs"})

	_ = pctx.SourcePathVariable("sAbiDiffer", "prebuilts/clang-tools/${config.HostPrebuiltTag}/bin/header-abi-diff")

	// Rule to compare linked sAbi dump files (.ldump).
	sAbiDiff = pctx.RuleFunc("sAbiDiff",
		func(ctx android.PackageRuleContext) blueprint.RuleParams {
			commandStr := "($sAbiDiffer ${extraFlags} -lib ${libName} -arch ${arch} -o ${out} -new ${in} -old ${referenceDump})"
			commandStr += "|| (echo '${errorMessage}'"
			commandStr += " && (mkdir -p $$DIST_DIR/abidiffs && cp ${out} $$DIST_DIR/abidiffs/)"
			commandStr += " && exit 1)"
			return blueprint.RuleParams{
				Command:     commandStr,
				CommandDeps: []string{"$sAbiDiffer"},
			}
		},
		"extraFlags", "referenceDump", "libName", "arch", "errorMessage")

	// Rule to zip files.
	zip = pctx.AndroidStaticRule("zip",
		blueprint.RuleParams{
			Command:        "${SoongZipCmd} -o ${out} -C $$OUT_DIR -r ${out}.rsp",
			CommandDeps:    []string{"${SoongZipCmd}"},
			Rspfile:        "${out}.rsp",
			RspfileContent: "$in",
		})

	_ = pctx.SourcePathVariable("cxxExtractor",
		"prebuilts/clang-tools/${config.HostPrebuiltTag}/bin/cxx_extractor")
	_ = pctx.SourcePathVariable("kytheVnames", "build/soong/vnames.json")
	_ = pctx.VariableFunc("kytheCorpus",
		func(ctx android.PackageVarContext) string { return ctx.Config().XrefCorpusName() })
	_ = pctx.VariableFunc("kytheCuEncoding",
		func(ctx android.PackageVarContext) string { return ctx.Config().XrefCuEncoding() })

	// Rule to use kythe extractors to generate .kzip files, used to build code cross references.
	kytheExtract = pctx.StaticRule("kythe",
		blueprint.RuleParams{
			Command: `rm -f $out && ` +
				`KYTHE_CORPUS=${kytheCorpus} ` +
				`KYTHE_OUTPUT_FILE=$out ` +
				`KYTHE_VNAMES=$kytheVnames ` +
				`KYTHE_KZIP_ENCODING=${kytheCuEncoding} ` +
				`KYTHE_CANONICALIZE_VNAME_PATHS=prefer-relative ` +
				`$cxxExtractor $cFlags $in `,
			CommandDeps: []string{"$cxxExtractor", "$kytheVnames"},
		},
		"cFlags")

	// Function pointer for producting staticlibs from rlibs. Corresponds to
	// rust.TransformRlibstoStaticlib(), initialized in soong-rust (rust/builder.go init())
	//
	// This is required since soong-rust depends on soong-cc, so soong-cc cannot depend on soong-rust
	// without resulting in a circular dependency. Setting this function pointer in soong-rust allows
	// soong-cc to call into this particular function.
	TransformRlibstoStaticlib (func(ctx android.ModuleContext, mainSrc android.Path, deps []RustRlibDep,
		outputFile android.WritablePath) android.Path) = nil
)

func PwdPrefix() string {
	// Darwin doesn't have /proc
	if runtime.GOOS != "darwin" {
		return "PWD=/proc/self/cwd"
	}
	return ""
}

func init() {
	// We run gcc/clang with PWD=/proc/self/cwd to remove $TOP from the
	// debug output. That way two builds in two different directories will
	// create the same output.
	pctx.StaticVariable("relPwd", PwdPrefix())

	pctx.HostBinToolVariable("SoongZipCmd", "soong_zip")
}

// builderFlags contains various types of command line flags (and settings) for use in building
// build statements related to C++.
type builderFlags struct {
	// Global flags (which build system or toolchain is responsible for). These are separate from
	// local flags because they should appear first (so that they may be overridden by local flags).
	globalCommonFlags     string
	globalAsFlags         string
	globalYasmFlags       string
	globalCFlags          string
	globalToolingCFlags   string // A separate set of cFlags for clang LibTooling tools
	globalToolingCppFlags string // A separate set of cppFlags for clang LibTooling tools
	globalConlyFlags      string
	globalCppFlags        string
	globalLdFlags         string

	// Local flags (which individual modules are responsible for). These may override global flags.
	localCommonFlags     string
	localAsFlags         string
	localYasmFlags       string
	localCFlags          string
	localToolingCFlags   string // A separate set of cFlags for clang LibTooling tools
	localToolingCppFlags string // A separate set of cppFlags for clang LibTooling tools
	localConlyFlags      string
	localCppFlags        string
	localLdFlags         string

	noOverrideFlags string // Flags appended at the end so they are not overridden.
	libFlags        string // Flags to add to the linker directly after specifying libraries to link.
	extraLibFlags   string // Flags to add to the linker last.
	tidyFlags       string // Flags that apply to clang-tidy
	sAbiFlags       string // Flags that apply to header-abi-dumps
	aidlFlags       string // Flags that apply to aidl source files
	rsFlags         string // Flags that apply to renderscript source files
	toolchain       config.Toolchain

	// True if these extra features are enabled.
	tidy          bool
	needTidyFiles bool
	gcovCoverage  bool
	sAbiDump      bool
	emitXrefs     bool
	clangVerify   bool

	assemblerWithCpp bool // True if .s files should be processed with the c preprocessor.

	systemIncludeFlags string

	proto            android.ProtoFlags
	protoC           bool // If true, compile protos as `.c` files. Otherwise, output as `.cc`.
	protoOptionsFile bool // If true, output a proto options file.

	yacc *YaccProperties
	lex  *LexProperties
}

// StripFlags represents flags related to stripping. This is separate from builderFlags, as these
// flags are useful outside of this package (such as for Rust).
type StripFlags struct {
	Toolchain                     config.Toolchain
	StripKeepSymbols              bool
	StripKeepSymbolsList          string
	StripKeepSymbolsAndDebugFrame bool
	StripKeepMiniDebugInfo        bool
	StripAddGnuDebuglink          bool
	StripUseGnuStrip              bool
}

// Objects is a collection of file paths corresponding to outputs for C++ related build statements.
type Objects struct {
	objFiles      android.Paths
	tidyFiles     android.Paths
	tidyDepFiles  android.Paths // link dependent .tidy files
	coverageFiles android.Paths
	sAbiDumpFiles android.Paths
	kytheFiles    android.Paths
}

func (a Objects) Copy() Objects {
	return Objects{
		objFiles:      append(android.Paths{}, a.objFiles...),
		tidyFiles:     append(android.Paths{}, a.tidyFiles...),
		tidyDepFiles:  append(android.Paths{}, a.tidyDepFiles...),
		coverageFiles: append(android.Paths{}, a.coverageFiles...),
		sAbiDumpFiles: append(android.Paths{}, a.sAbiDumpFiles...),
		kytheFiles:    append(android.Paths{}, a.kytheFiles...),
	}
}

func (a Objects) Append(b Objects) Objects {
	return Objects{
		objFiles:      append(a.objFiles, b.objFiles...),
		tidyFiles:     append(a.tidyFiles, b.tidyFiles...),
		tidyDepFiles:  append(a.tidyDepFiles, b.tidyDepFiles...),
		coverageFiles: append(a.coverageFiles, b.coverageFiles...),
		sAbiDumpFiles: append(a.sAbiDumpFiles, b.sAbiDumpFiles...),
		kytheFiles:    append(a.kytheFiles, b.kytheFiles...),
	}
}

// Generate rules for compiling multiple .c, .cpp, or .S files to individual .o files
func transformSourceToObj(ctx android.ModuleContext, subdir string, srcFiles, noTidySrcs, timeoutTidySrcs android.Paths,
	flags builderFlags, pathDeps android.Paths, cFlagsDeps android.Paths, sharedFlags *SharedFlags) Objects {

	// Not all source files produce a .o; a Rust source provider
	// may provide both a .c and a .rs file (e.g. rust_bindgen).
	srcObjFiles := android.Paths{}
	for _, src := range srcFiles {
		if src.Ext() != ".rs" {
			srcObjFiles = append(srcObjFiles, src)
		}
	}

	// Source files are one-to-one with tidy, coverage, or kythe files, if enabled.
	objFiles := make(android.Paths, len(srcObjFiles))
	var tidyFiles android.Paths
	noTidySrcsMap := make(map[string]bool)
	var tidyVars string
	if flags.tidy {
		tidyFiles = make(android.Paths, 0, len(srcObjFiles))
		for _, path := range noTidySrcs {
			noTidySrcsMap[path.String()] = true
		}
		tidyTimeout := ctx.Config().Getenv("TIDY_TIMEOUT")
		if len(tidyTimeout) > 0 {
			tidyVars += "TIDY_TIMEOUT=" + tidyTimeout + " "
			// add timeoutTidySrcs into noTidySrcsMap if TIDY_TIMEOUT is set
			for _, path := range timeoutTidySrcs {
				noTidySrcsMap[path.String()] = true
			}
		}
	}
	var coverageFiles android.Paths
	if flags.gcovCoverage {
		coverageFiles = make(android.Paths, 0, len(srcObjFiles))
	}
	var kytheFiles android.Paths
	if flags.emitXrefs && ctx.Module() == ctx.PrimaryModule() {
		kytheFiles = make(android.Paths, 0, len(srcObjFiles))
	}

	// Produce fully expanded flags for use by C tools, C compiles, C++ tools, C++ compiles, and asm compiles
	// respectively.
	toolingCflags := flags.globalCommonFlags + " " +
		flags.globalToolingCFlags + " " +
		flags.globalConlyFlags + " " +
		flags.localCommonFlags + " " +
		flags.localToolingCFlags + " " +
		flags.localConlyFlags + " " +
		flags.systemIncludeFlags + " " +
		flags.noOverrideFlags

	cflags := flags.globalCommonFlags + " " +
		flags.globalCFlags + " " +
		flags.globalConlyFlags + " " +
		flags.localCommonFlags + " " +
		flags.localCFlags + " " +
		flags.localConlyFlags + " " +
		flags.systemIncludeFlags + " " +
		flags.noOverrideFlags

	toolingCppflags := flags.globalCommonFlags + " " +
		flags.globalToolingCFlags + " " +
		flags.globalToolingCppFlags + " " +
		flags.localCommonFlags + " " +
		flags.localToolingCFlags + " " +
		flags.localToolingCppFlags + " " +
		flags.systemIncludeFlags + " " +
		flags.noOverrideFlags

	cppflags := flags.globalCommonFlags + " " +
		flags.globalCFlags + " " +
		flags.globalCppFlags + " " +
		flags.localCommonFlags + " " +
		flags.localCFlags + " " +
		flags.localCppFlags + " " +
		flags.systemIncludeFlags + " " +
		flags.noOverrideFlags

	asflags := flags.globalCommonFlags + " " +
		flags.globalAsFlags + " " +
		flags.localCommonFlags + " " +
		flags.localAsFlags + " " +
		flags.systemIncludeFlags

	var sAbiDumpFiles android.Paths
	if flags.sAbiDump {
		sAbiDumpFiles = make(android.Paths, 0, len(srcObjFiles))
	}

	// Multiple source files have build rules usually share the same cFlags or tidyFlags.
	// SharedFlags provides one version for this module and shares it in multiple build rules.
	// To simplify the code, the SharedFlags variables are all named as $flags<nnn>.
	// Share flags only when there are multiple files or tidy rules.
	var hasMultipleRules = len(srcObjFiles) > 1 || flags.tidy

	var shareFlags = func(kind string, flags string) string {
		if !hasMultipleRules || len(flags) < 60 {
			// Modules have long names and so do the module variables.
			// It does not save space by replacing a short name with a long one.
			return flags
		}
		mapKey := kind + flags
		n, ok := sharedFlags.FlagsMap[mapKey]
		if !ok {
			sharedFlags.NumSharedFlags += 1
			n = strconv.Itoa(sharedFlags.NumSharedFlags)
			sharedFlags.FlagsMap[mapKey] = n
			ctx.Variable(pctx, kind+n, flags)
		}
		return "$" + kind + n
	}

	for i, srcFile := range srcObjFiles {
		objFile := android.ObjPathWithExt(ctx, subdir, srcFile, "o")

		objFiles[i] = objFile

		// Register compilation build statements. The actual rule used depends on the source file type.
		switch srcFile.Ext() {
		case ".asm":
			ctx.Build(pctx, android.BuildParams{
				Rule:        yasm,
				Description: "yasm " + srcFile.Rel(),
				Output:      objFile,
				Input:       srcFile,
				Implicits:   cFlagsDeps,
				OrderOnly:   pathDeps,
				Args: map[string]string{
					"asFlags": shareFlags("asFlags", flags.globalYasmFlags+" "+flags.localYasmFlags),
				},
			})
			continue
		case ".o":
			objFiles[i] = srcFile
			continue
		}

		var moduleFlags string
		var moduleToolingFlags string

		var ccCmd string
		var postCmd string
		tidy := flags.tidy
		coverage := flags.gcovCoverage
		dump := flags.sAbiDump
		rule := cc
		emitXref := flags.emitXrefs

		switch srcFile.Ext() {
		case ".s":
			if !flags.assemblerWithCpp {
				rule = ccNoDeps
			}
			fallthrough
		case ".S":
			ccCmd = "clang"
			moduleFlags = asflags
			tidy = false
			coverage = false
			dump = false
			emitXref = false
		case ".c":
			ccCmd = "clang"
			moduleFlags = cflags
			moduleToolingFlags = toolingCflags
		case ".cpp", ".cc", ".cxx", ".mm":
			ccCmd = "clang++"
			moduleFlags = cppflags
			moduleToolingFlags = toolingCppflags
		case ".rs":
			// A source provider (e.g. rust_bindgen) may provide both rs and c files.
			// Ignore the rs files.
			continue
		case ".h", ".hpp":
			ctx.PropertyErrorf("srcs", "Header file %s is not supported, instead use export_include_dirs or local_include_dirs.", srcFile)
			continue
		default:
			ctx.PropertyErrorf("srcs", "File %s has unknown extension. Supported extensions: .s, .S, .c, .cpp, .cc, .cxx, .mm", srcFile)
			continue
		}

		// ccCmd is "clang" or "clang++"
		ccDesc := ccCmd

		ccCmd = "${config.ClangBin}/" + ccCmd

		if flags.clangVerify {
			postCmd = " && touch " + objFile.String()
		}

		var implicitOutputs android.WritablePaths
		if coverage {
			gcnoFile := android.ObjPathWithExt(ctx, subdir, srcFile, "gcno")
			implicitOutputs = append(implicitOutputs, gcnoFile)
			coverageFiles = append(coverageFiles, gcnoFile)
		}

		ctx.Build(pctx, android.BuildParams{
			Rule:            rule,
			Description:     ccDesc + " " + srcFile.Rel(),
			Output:          objFile,
			ImplicitOutputs: implicitOutputs,
			Input:           srcFile,
			Implicits:       cFlagsDeps,
			OrderOnly:       pathDeps,
			Args: map[string]string{
				"cFlags":  shareFlags("cFlags", moduleFlags),
				"ccCmd":   ccCmd, // short and not shared
				"postCmd": postCmd,
			},
		})

		// Register post-process build statements (such as for tidy or kythe).
		if emitXref && ctx.Module() == ctx.PrimaryModule() {
			kytheFile := android.ObjPathWithExt(ctx, subdir, srcFile, "kzip")
			ctx.Build(pctx, android.BuildParams{
				Rule:        kytheExtract,
				Description: "Xref C++ extractor " + srcFile.Rel(),
				Output:      kytheFile,
				Input:       srcFile,
				Implicits:   cFlagsDeps,
				OrderOnly:   pathDeps,
				Args: map[string]string{
					"cFlags": shareFlags("cFlags", moduleFlags),
				},
			})
			kytheFiles = append(kytheFiles, kytheFile)
		}

		//  Even with tidy, some src file could be skipped by noTidySrcsMap.
		if tidy && !noTidySrcsMap[srcFile.String()] {
			tidyFile := android.ObjPathWithExt(ctx, subdir, srcFile, "tidy")
			tidyFiles = append(tidyFiles, tidyFile)
			tidyCmd := "${config.ClangBin}/clang-tidy"

			rule := clangTidy
			if ctx.Config().UseRBE() && ctx.Config().IsEnvTrue("RBE_CLANG_TIDY") {
				rule = clangTidyRE
			}

			sharedCFlags := shareFlags("cFlags", moduleFlags)
			srcRelPath := srcFile.Rel()

			// Add the .tidy rule
			ctx.Build(pctx, android.BuildParams{
				Rule:        rule,
				Description: "clang-tidy " + srcRelPath,
				Output:      tidyFile,
				Input:       srcFile,
				Implicits:   cFlagsDeps,
				OrderOnly:   pathDeps,
				Args: map[string]string{
					"cFlags":    sharedCFlags,
					"ccCmd":     ccCmd,
					"clangCmd":  ccDesc,
					"tidyCmd":   tidyCmd,
					"tidyFlags": shareFlags("tidyFlags", config.TidyFlagsForSrcFile(srcFile, flags.tidyFlags)),
					"tidyVars":  tidyVars, // short and not shared
				},
			})
		}

		if dump {
			sAbiDumpFile := android.ObjPathWithExt(ctx, subdir, srcFile, "sdump")
			sAbiDumpFiles = append(sAbiDumpFiles, sAbiDumpFile)

			dumpRule := sAbiDump
			if ctx.Config().UseRBE() && ctx.Config().IsEnvTrue("RBE_ABI_DUMPER") {
				dumpRule = sAbiDumpRE
			}
			ctx.Build(pctx, android.BuildParams{
				Rule:        dumpRule,
				Description: "header-abi-dumper " + srcFile.Rel(),
				Output:      sAbiDumpFile,
				Input:       srcFile,
				Implicit:    objFile,
				Implicits:   cFlagsDeps,
				OrderOnly:   pathDeps,
				Args: map[string]string{
					"cFlags":     shareFlags("cFlags", moduleToolingFlags),
					"exportDirs": shareFlags("exportDirs", flags.sAbiFlags),
				},
			})
		}

	}

	var tidyDepFiles android.Paths
	if flags.needTidyFiles {
		tidyDepFiles = tidyFiles
	}
	return Objects{
		objFiles:      objFiles,
		tidyFiles:     tidyFiles,
		tidyDepFiles:  tidyDepFiles,
		coverageFiles: coverageFiles,
		sAbiDumpFiles: sAbiDumpFiles,
		kytheFiles:    kytheFiles,
	}
}

// Generate a rule for compiling multiple .o files to a static library (.a)
func transformObjToStaticLib(ctx android.ModuleContext,
	objFiles android.Paths, wholeStaticLibs android.Paths,
	flags builderFlags, outputFile android.ModuleOutPath, deps android.Paths, validations android.Paths) {

	arCmd := "${config.ClangBin}/llvm-ar"
	arFlags := ""
	if !ctx.Darwin() {
		arFlags += " --format=gnu"
	}

	if len(wholeStaticLibs) == 0 {
		ctx.Build(pctx, android.BuildParams{
			Rule:        ar,
			Description: "static link " + outputFile.Base(),
			Output:      outputFile,
			Inputs:      objFiles,
			Implicits:   deps,
			Validations: validations,
			Args: map[string]string{
				"arFlags": "crsPD" + arFlags,
				"arCmd":   arCmd,
			},
		})

	} else {
		ctx.Build(pctx, android.BuildParams{
			Rule:        arWithLibs,
			Description: "static link " + outputFile.Base(),
			Output:      outputFile,
			Inputs:      append(objFiles, wholeStaticLibs...),
			Implicits:   deps,
			Args: map[string]string{
				"arCmd":      arCmd,
				"arObjFlags": "crsPD" + arFlags,
				"arObjs":     strings.Join(objFiles.Strings(), " "),
				"arLibFlags": "cqsL" + arFlags,
				"arLibs":     strings.Join(wholeStaticLibs.Strings(), " "),
			},
		})
	}
}

// Generate a Rust staticlib from a list of rlibDeps. Returns nil if TransformRlibstoStaticlib is nil or rlibDeps is empty.
func GenerateRustStaticlib(ctx android.ModuleContext, rlibDeps []RustRlibDep) android.Path {
	if TransformRlibstoStaticlib == nil && len(rlibDeps) > 0 {
		// This should only be reachable if a module defines Rust deps in static_libs and
		// soong-rust hasn't been loaded alongside soong-cc (e.g. in soong-cc tests).
		panic(fmt.Errorf(
			"TransformRlibstoStaticlib is not set and rust deps are defined in static_libs for %s",
			ctx.ModuleName()))

	} else if len(rlibDeps) == 0 {
		return nil
	}

	output := android.PathForModuleOut(ctx, "generated_rust_staticlib", "librustlibs.a")
	stemFile := output.ReplaceExtension(ctx, "rs")
	crateNames := []string{}

	// Collect crate names
	for _, lib := range rlibDeps {
		// Exclude libstd so this can support no_std builds.
		if lib.CrateName != "libstd" {
			crateNames = append(crateNames, lib.CrateName)
		}
	}

	// Deduplicate any crateNames just to be safe
	crateNames = android.FirstUniqueStrings(crateNames)

	// Write the source file
	android.WriteFileRule(ctx, stemFile, genRustStaticlibSrcFile(crateNames))

	return TransformRlibstoStaticlib(ctx, stemFile, rlibDeps, output)
}

func genRustStaticlibSrcFile(crateNames []string) string {
	lines := []string{
		"// @Soong generated Source",
		"#![no_std]", // pre-emptively set no_std to support both std and no_std.
	}
	for _, crate := range crateNames {
		lines = append(lines, fmt.Sprintf("extern crate %s;", crate))
	}
	return strings.Join(lines, "\n")
}

func BuildRustStubs(ctx android.ModuleContext, outputFile android.ModuleOutPath,
	stubObjs Objects, ccFlags Flags) {

	// Instantiate paths
	sharedLibs := android.Paths{}
	staticLibs := android.Paths{}
	lateStaticLibs := android.Paths{}
	wholeStaticLibs := android.Paths{}
	deps := android.Paths{}
	implicitOutputs := android.WritablePaths{}
	validations := android.Paths{}
	crtBegin := android.Paths{}
	crtEnd := android.Paths{}
	groupLate := false

	builderFlags := flagsToBuilderFlags(ccFlags)
	transformObjToDynamicBinary(ctx, stubObjs.objFiles, sharedLibs, staticLibs,
		lateStaticLibs, wholeStaticLibs, deps, crtBegin, crtEnd,
		groupLate, builderFlags, outputFile, implicitOutputs, validations)
}

// Generate a rule for compiling multiple .o files, plus static libraries, whole static libraries,
// and shared libraries, to a shared library (.so) or dynamic executable
func transformObjToDynamicBinary(ctx android.ModuleContext,
	objFiles, sharedLibs, staticLibs, lateStaticLibs, wholeStaticLibs, deps, crtBegin, crtEnd android.Paths,
	groupLate bool, flags builderFlags, outputFile android.WritablePath,
	implicitOutputs android.WritablePaths, validations android.Paths) {

	ldCmd := "${config.ClangBin}/clang++"

	var libFlagsList []string

	if len(flags.libFlags) > 0 {
		libFlagsList = append(libFlagsList, flags.libFlags)
	}

	if len(wholeStaticLibs) > 0 {
		if ctx.Host() && ctx.Darwin() {
			libFlagsList = append(libFlagsList, android.JoinWithPrefix(wholeStaticLibs.Strings(), "-force_load "))
		} else {
			libFlagsList = append(libFlagsList, "-Wl,--whole-archive ")
			libFlagsList = append(libFlagsList, wholeStaticLibs.Strings()...)
			libFlagsList = append(libFlagsList, "-Wl,--no-whole-archive ")
		}
	}

	libFlagsList = append(libFlagsList, staticLibs.Strings()...)

	if groupLate && !ctx.Darwin() && len(lateStaticLibs) > 0 {
		libFlagsList = append(libFlagsList, "-Wl,--start-group")
	}
	libFlagsList = append(libFlagsList, lateStaticLibs.Strings()...)
	if groupLate && !ctx.Darwin() && len(lateStaticLibs) > 0 {
		libFlagsList = append(libFlagsList, "-Wl,--end-group")
	}

	for _, lib := range sharedLibs {
		libFile := lib.String()
		if ctx.Windows() {
			libFile = pathtools.ReplaceExtension(libFile, "lib")
		}
		libFlagsList = append(libFlagsList, libFile)
	}

	deps = append(deps, staticLibs...)
	deps = append(deps, lateStaticLibs...)
	deps = append(deps, wholeStaticLibs...)
	deps = append(deps, crtBegin...)
	deps = append(deps, crtEnd...)

	rule := ld
	args := map[string]string{
		"ldCmd":         ldCmd,
		"crtBegin":      strings.Join(crtBegin.Strings(), " "),
		"libFlags":      strings.Join(libFlagsList, " "),
		"extraLibFlags": flags.extraLibFlags,
		"ldFlags":       flags.globalLdFlags + " " + flags.localLdFlags,
		"crtEnd":        strings.Join(crtEnd.Strings(), " "),
	}

	// On Windows, we always generate a PDB file
	// --strip-debug is needed to also keep COFF symbols which are needed when
	// we patch binaries with symbol_inject.
	if ctx.Windows() {
		pdb := outputFile.ReplaceExtension(ctx, "pdb")
		args["ldFlags"] = args["ldFlags"] + " -Wl,--strip-debug -Wl,--pdb=" + pdb.String() + " "
		implicitOutputs = append(slices.Clone(implicitOutputs), pdb)
	}

	if ctx.Config().UseRBE() && ctx.Config().IsEnvTrue("RBE_CXX_LINKS") {
		rule = ldRE
		args["implicitOutputs"] = strings.Join(implicitOutputs.Strings(), ",")
		args["implicitInputs"] = strings.Join(deps.Strings(), ",")
	}

	ctx.Build(pctx, android.BuildParams{
		Rule:            rule,
		Description:     "link " + outputFile.Base(),
		Output:          outputFile,
		ImplicitOutputs: implicitOutputs,
		Inputs:          objFiles,
		Implicits:       deps,
		OrderOnly:       sharedLibs,
		Validations:     validations,
		Args:            args,
	})
}

// Generate a rule to combine .dump sAbi dump files from multiple source files
// into a single .ldump sAbi dump file
func transformDumpToLinkedDump(ctx android.ModuleContext, sAbiDumps android.Paths, soFile android.Path,
	baseName string, exportedIncludeDirs []string, symbolFile android.OptionalPath,
	excludedSymbolVersions, excludedSymbolTags, includedSymbolTags []string,
	api string, commonGlobalIncludes bool) android.Path {

	outputFile := android.PathForModuleOut(ctx, baseName+".lsdump")

	implicits := android.Paths{soFile}
	symbolFilterStr := "-so " + soFile.String()
	exportedHeaderFlags := android.JoinWithPrefix(exportedIncludeDirs, "-I")
	// If this library does not export any include directory, do not append the flags
	// so that the ABI tool dumps everything without filtering by the include directories.
	if commonGlobalIncludes && len(exportedIncludeDirs) > 0 {
		exportedHeaderFlags += " ${config.CommonGlobalIncludes}"
	}

	if symbolFile.Valid() {
		implicits = append(implicits, symbolFile.Path())
		symbolFilterStr += " -v " + symbolFile.String()
	}
	for _, ver := range excludedSymbolVersions {
		symbolFilterStr += " --exclude-symbol-version " + ver
	}
	for _, tag := range excludedSymbolTags {
		symbolFilterStr += " --exclude-symbol-tag " + tag
	}
	for _, tag := range includedSymbolTags {
		symbolFilterStr += " --include-symbol-tag " + tag
	}
	apiLevelsJson := android.GetApiLevelsJson(ctx)
	implicits = append(implicits, apiLevelsJson)
	symbolFilterStr += " --api-map " + apiLevelsJson.String()
	symbolFilterStr += " --api " + api

	rule := sAbiLink
	args := map[string]string{
		"symbolFilter":        symbolFilterStr,
		"arch":                ctx.Arch().ArchType.Name,
		"exportedHeaderFlags": exportedHeaderFlags,
	}
	if ctx.Config().UseRBE() && ctx.Config().IsEnvTrue("RBE_ABI_LINKER") {
		rule = sAbiLinkRE
		rbeImplicits := append(implicits.Strings(), exportedIncludeDirs...)
		args["implicitInputs"] = strings.Join(rbeImplicits, ",")
	}
	ctx.Build(pctx, android.BuildParams{
		Rule:        rule,
		Description: "header-abi-linker " + outputFile.Base(),
		Output:      outputFile,
		Inputs:      sAbiDumps,
		Implicits:   implicits,
		Args:        args,
	})
	return outputFile
}

func transformAbiDumpToAbiDiff(ctx android.ModuleContext, inputDump, referenceDump android.Path,
	baseName, nameExt string, extraFlags []string, errorMessage string) android.Path {

	var outputFile android.ModuleOutPath
	if nameExt != "" {
		outputFile = android.PathForModuleOut(ctx, baseName+"."+nameExt+".abidiff")
	} else {
		outputFile = android.PathForModuleOut(ctx, baseName+".abidiff")
	}
	libName := strings.TrimSuffix(baseName, filepath.Ext(baseName))

	ctx.Build(pctx, android.BuildParams{
		Rule:        sAbiDiff,
		Description: "header-abi-diff " + outputFile.Base(),
		Output:      outputFile,
		Input:       inputDump,
		Implicit:    referenceDump,
		Args: map[string]string{
			"referenceDump": referenceDump.String(),
			"libName":       libName,
			"arch":          ctx.Arch().ArchType.Name,
			"extraFlags":    strings.Join(extraFlags, " "),
			"errorMessage":  errorMessage,
		},
	})
	return outputFile
}

// Generate a rule for extracting a table of contents from a shared library (.so)
func TransformSharedObjectToToc(ctx android.ModuleContext, inputFile android.Path, outputFile android.WritablePath) {

	var format string
	if ctx.Darwin() {
		format = "--macho"
	} else if ctx.Windows() {
		format = "--pe"
	} else {
		format = "--elf"
	}

	ctx.Build(pctx, android.BuildParams{
		Rule:        toc,
		Description: "generate toc " + inputFile.Base(),
		Output:      outputFile,
		Input:       inputFile,
		Args: map[string]string{
			"clangBin": "${config.ClangBin}",
			"format":   format,
		},
	})
}

// Generate a rule for compiling multiple .o files to a .o using ld partial linking
func transformObjsToObj(ctx android.ModuleContext, objFiles android.Paths,
	flags builderFlags, outputFile android.WritablePath, deps android.Paths) {

	ldCmd := "${config.ClangBin}/clang++"

	rule := partialLd
	args := map[string]string{
		"ldCmd":   ldCmd,
		"ldFlags": flags.globalLdFlags + " " + flags.localLdFlags,
	}
	if ctx.Config().UseRBE() && ctx.Config().IsEnvTrue("RBE_CXX_LINKS") {
		rule = partialLdRE
		args["inCommaList"] = strings.Join(objFiles.Strings(), ",")
		args["implicitInputs"] = strings.Join(deps.Strings(), ",")
	}
	ctx.Build(pctx, android.BuildParams{
		Rule:        rule,
		Description: "link " + outputFile.Base(),
		Output:      outputFile,
		Inputs:      objFiles,
		Implicits:   deps,
		Args:        args,
	})
}

// Generate a rule for running objcopy --prefix-symbols on a binary
func transformBinaryPrefixSymbols(ctx android.ModuleContext, prefix string, inputFile android.Path,
	flags builderFlags, outputFile android.WritablePath) {

	objcopyCmd := "${config.ClangBin}/llvm-objcopy"

	ctx.Build(pctx, android.BuildParams{
		Rule:        prefixSymbols,
		Description: "prefix symbols " + outputFile.Base(),
		Output:      outputFile,
		Input:       inputFile,
		Args: map[string]string{
			"objcopyCmd": objcopyCmd,
			"prefix":     prefix,
		},
	})
}

// Generate a rule for running objcopy --remove-section=.llvm_addrsig on a partially linked object
func transformObjectNoAddrSig(ctx android.ModuleContext, inputFile android.Path, outputFile android.WritablePath) {
	objcopyCmd := "${config.ClangBin}/llvm-objcopy"

	ctx.Build(pctx, android.BuildParams{
		Rule:        noAddrSig,
		Description: "remove addrsig " + outputFile.Base(),
		Output:      outputFile,
		Input:       inputFile,
		Args: map[string]string{
			"objcopyCmd": objcopyCmd,
		},
	})
}

// Registers a build statement to invoke `strip` (to discard symbols and data from object files).
func transformStrip(ctx android.ModuleContext, inputFile android.Path,
	outputFile android.WritablePath, flags StripFlags) {

	args := ""
	if flags.StripAddGnuDebuglink {
		args += " --add-gnu-debuglink"
	}
	if flags.StripKeepMiniDebugInfo {
		args += " --keep-mini-debug-info"
	}
	if flags.StripKeepSymbols {
		args += " --keep-symbols"
	}
	if flags.StripKeepSymbolsList != "" {
		args += " -k" + flags.StripKeepSymbolsList
	}
	if flags.StripKeepSymbolsAndDebugFrame {
		args += " --keep-symbols-and-debug-frame"
	}
	if ctx.Windows() {
		args += " --windows"
	}

	ctx.Build(pctx, android.BuildParams{
		Rule:        strip,
		Description: "strip " + outputFile.Base(),
		Output:      outputFile,
		Input:       inputFile,
		Args: map[string]string{
			"args": args,
		},
	})
}

// Registers build statement to invoke `strip` on darwin architecture.
func transformDarwinStrip(ctx android.ModuleContext, inputFile android.Path,
	outputFile android.WritablePath) {

	ctx.Build(pctx, android.BuildParams{
		Rule:        darwinStrip,
		Description: "strip " + outputFile.Base(),
		Output:      outputFile,
		Input:       inputFile,
	})
}

func transformDarwinUniversalBinary(ctx android.ModuleContext, outputFile android.WritablePath, inputFiles ...android.Path) {
	ctx.Build(pctx, android.BuildParams{
		Rule:        darwinLipo,
		Description: "lipo " + outputFile.Base(),
		Output:      outputFile,
		Inputs:      inputFiles,
	})
}

// Registers build statement to zip one or more coverage files.
func transformCoverageFilesToZip(ctx android.ModuleContext,
	inputs Objects, baseName string) android.OptionalPath {

	if len(inputs.coverageFiles) > 0 {
		outputFile := android.PathForModuleOut(ctx, baseName+".zip")

		ctx.Build(pctx, android.BuildParams{
			Rule:        zip,
			Description: "zip " + outputFile.Base(),
			Inputs:      inputs.coverageFiles,
			Output:      outputFile,
		})

		return android.OptionalPathForPath(outputFile)
	}

	return android.OptionalPath{}
}

// Rule to repack an archive (.a) file with a subset of object files.
func transformArchiveRepack(ctx android.ModuleContext, inputFile android.Path,
	outputFile android.WritablePath, objects []string) {

	ctx.Build(pctx, android.BuildParams{
		Rule:        archiveRepack,
		Description: "Repack archive " + outputFile.Base(),
		Output:      outputFile,
		Input:       inputFile,
		Args: map[string]string{
			"objects": strings.Join(objects, " "),
		},
	})
}
