// Copyright (C) 2018 The Android Open Source Project
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

package bpf

import (
	"fmt"
	"io"
	"path/filepath"
	"runtime"
	"strings"

	"android/soong/android"
	"android/soong/cc"

	"github.com/google/blueprint"
	"github.com/google/blueprint/proptools"
)

func init() {
	registerBpfBuildComponents(android.InitRegistrationContext)
	pctx.Import("android/soong/cc/config")
	pctx.StaticVariable("relPwd", cc.PwdPrefix())
}

var (
	pctx = android.NewPackageContext("android/soong/bpf")

	ccRule = pctx.AndroidRemoteStaticRule("ccRule", android.RemoteRuleSupports{Goma: true},
		blueprint.RuleParams{
			Depfile:     "${out}.d",
			Deps:        blueprint.DepsGCC,
			Command:     "$relPwd $ccCmd --target=bpf -c $cFlags -MD -MF ${out}.d -o $out $in",
			CommandDeps: []string{"$ccCmd"},
		},
		"ccCmd", "cFlags")

	stripRule = pctx.AndroidStaticRule("stripRule",
		blueprint.RuleParams{
			Command: `$stripCmd --strip-unneeded --remove-section=.rel.BTF ` +
				`--remove-section=.rel.BTF.ext --remove-section=.BTF.ext $in -o $out`,
			CommandDeps: []string{"$stripCmd"},
		},
		"stripCmd")
)

func registerBpfBuildComponents(ctx android.RegistrationContext) {
	ctx.RegisterModuleType("bpf_defaults", defaultsFactory)
	ctx.RegisterModuleType("bpf", BpfFactory)
}

type BpfInfo struct {
	SubDir string
}

var BpfInfoProvider = blueprint.NewProvider[BpfInfo]()

var PrepareForTestWithBpf = android.FixtureRegisterWithContext(registerBpfBuildComponents)

// BpfModule interface is used by the apex package to gather information from a bpf module.
type BpfModule interface {
	android.Module

	// Returns the sub install directory if the bpf module is included by apex.
	SubDir() string
}

type BpfProperties struct {
	// source paths to the files.
	Srcs []string `android:"path"`

	// additional cflags that should be used to build the bpf variant of
	// the C/C++ module.
	Cflags []string

	// list of directories relative to the root of the source tree that
	// will be added to the include paths using -I.
	// If possible, don't use this. If adding paths from the current
	// directory, use local_include_dirs. If adding paths from other
	// modules, use export_include_dirs in that module.
	Include_dirs []string

	// list of directories relative to the Blueprint file that will be
	// added to the include path using -I.
	Local_include_dirs []string
	// optional subdirectory under which this module is installed into.
	Sub_dir string

	// if set to true, generate BTF debug info for maps & programs.
	Btf *bool

	Vendor *bool

	VendorInternal bool `blueprint:"mutated"`
}

type bpf struct {
	android.ModuleBase
	android.DefaultableModuleBase
	properties BpfProperties

	objs android.Paths
}

var _ android.ImageInterface = (*bpf)(nil)

func (bpf *bpf) ImageMutatorBegin(ctx android.ImageInterfaceContext) {}

func (bpf *bpf) VendorVariantNeeded(ctx android.ImageInterfaceContext) bool {
	return proptools.Bool(bpf.properties.Vendor)
}

func (bpf *bpf) ProductVariantNeeded(ctx android.ImageInterfaceContext) bool {
	return false
}

func (bpf *bpf) CoreVariantNeeded(ctx android.ImageInterfaceContext) bool {
	return !proptools.Bool(bpf.properties.Vendor)
}

func (bpf *bpf) RamdiskVariantNeeded(ctx android.ImageInterfaceContext) bool {
	return false
}

func (bpf *bpf) VendorRamdiskVariantNeeded(ctx android.ImageInterfaceContext) bool {
	return false
}

func (bpf *bpf) DebugRamdiskVariantNeeded(ctx android.ImageInterfaceContext) bool {
	return false
}

func (bpf *bpf) RecoveryVariantNeeded(ctx android.ImageInterfaceContext) bool {
	return false
}

func (bpf *bpf) ExtraImageVariations(ctx android.ImageInterfaceContext) []string {
	return nil
}

func (bpf *bpf) SetImageVariation(ctx android.ImageInterfaceContext, variation string) {
	bpf.properties.VendorInternal = variation == "vendor"
}

func (bpf *bpf) GenerateAndroidBuildActions(ctx android.ModuleContext) {
	cflags := []string{
		"-nostdlibinc",

		// Make paths in deps files relative
		"-no-canonical-prefixes",

		"-O2",
		"-Wall",
		"-Werror",
		"-Wextra",

		"-isystem bionic/libc/include",
		"-isystem bionic/libc/kernel/uapi",
		// The architecture doesn't matter here, but asm/types.h is included by linux/types.h.
		"-isystem bionic/libc/kernel/uapi/asm-arm64",
		"-isystem bionic/libc/kernel/android/uapi",
		"-I       packages/modules/Connectivity/bpf/headers/include",
		// TODO(b/149785767): only give access to specific file with AID_* constants
		"-I       system/core/libcutils/include",
		"-I " + ctx.ModuleDir(),
	}

	for _, dir := range android.PathsForModuleSrc(ctx, bpf.properties.Local_include_dirs) {
		cflags = append(cflags, "-I "+dir.String())
	}

	for _, dir := range android.PathsForSource(ctx, bpf.properties.Include_dirs) {
		cflags = append(cflags, "-I "+dir.String())
	}

	cflags = append(cflags, bpf.properties.Cflags...)

	if proptools.BoolDefault(bpf.properties.Btf, true) {
		cflags = append(cflags, "-g")
		if runtime.GOOS != "darwin" {
			cflags = append(cflags, "-fdebug-prefix-map=/proc/self/cwd=")
		}
	}

	srcs := android.PathsForModuleSrc(ctx, bpf.properties.Srcs)

	for _, src := range srcs {
		if strings.ContainsRune(filepath.Base(src.String()), '_') {
			ctx.ModuleErrorf("invalid character '_' in source name")
		}
		obj := android.ObjPathWithExt(ctx, "unstripped", src, "o")

		ctx.Build(pctx, android.BuildParams{
			Rule:   ccRule,
			Input:  src,
			Output: obj,
			Args: map[string]string{
				"cFlags": strings.Join(cflags, " "),
				"ccCmd":  "${config.ClangBin}/clang",
			},
		})

		if proptools.BoolDefault(bpf.properties.Btf, true) {
			objStripped := android.ObjPathWithExt(ctx, "", src, "o")
			ctx.Build(pctx, android.BuildParams{
				Rule:   stripRule,
				Input:  obj,
				Output: objStripped,
				Args: map[string]string{
					"stripCmd": "${config.ClangBin}/llvm-strip",
				},
			})
			bpf.objs = append(bpf.objs, objStripped.WithoutRel())
		} else {
			bpf.objs = append(bpf.objs, obj.WithoutRel())
		}

	}

	installDir := android.PathForModuleInstall(ctx, "etc", "bpf")
	if len(bpf.properties.Sub_dir) > 0 {
		installDir = installDir.Join(ctx, bpf.properties.Sub_dir)
	}
	for _, obj := range bpf.objs {
		ctx.PackageFile(installDir, obj.Base(), obj)
	}

	android.SetProvider(ctx, BpfInfoProvider, BpfInfo{
		SubDir: bpf.SubDir(),
	})

	ctx.SetOutputFiles(bpf.objs, "")
}

func (bpf *bpf) AndroidMk() android.AndroidMkData {
	return android.AndroidMkData{
		Custom: func(w io.Writer, name, prefix, moduleDir string, data android.AndroidMkData) {
			var names []string
			fmt.Fprintln(w)
			fmt.Fprintln(w, "LOCAL_PATH :=", moduleDir)
			fmt.Fprintln(w)
			var localModulePath string
			if bpf.properties.VendorInternal {
				localModulePath = "LOCAL_MODULE_PATH := $(TARGET_OUT_VENDOR_ETC)/bpf"
			} else {
				localModulePath = "LOCAL_MODULE_PATH := $(TARGET_OUT_ETC)/bpf"
			}
			if len(bpf.properties.Sub_dir) > 0 {
				localModulePath += "/" + bpf.properties.Sub_dir
			}
			for _, obj := range bpf.objs {
				objName := name + "_" + obj.Base()
				names = append(names, objName)
				fmt.Fprintln(w, "include $(CLEAR_VARS)", " # bpf.bpf.obj")
				fmt.Fprintln(w, "LOCAL_MODULE := ", objName)
				fmt.Fprintln(w, "LOCAL_PREBUILT_MODULE_FILE :=", obj.String())
				fmt.Fprintln(w, "LOCAL_MODULE_STEM :=", obj.Base())
				fmt.Fprintln(w, "LOCAL_MODULE_CLASS := ETC")
				fmt.Fprintln(w, localModulePath)
				// AconfigUpdateAndroidMkData may have added elements to Extra.  Process them here.
				for _, extra := range data.Extra {
					extra(w, nil)
				}
				fmt.Fprintln(w, "include $(BUILD_PREBUILT)")
				fmt.Fprintln(w)
			}
			fmt.Fprintln(w, "include $(CLEAR_VARS)", " # bpf.bpf")
			fmt.Fprintln(w, "LOCAL_MODULE := ", name)
			android.AndroidMkEmitAssignList(w, "LOCAL_REQUIRED_MODULES", names)
			fmt.Fprintln(w, "include $(BUILD_PHONY_PACKAGE)")
		},
	}
}

type Defaults struct {
	android.ModuleBase
	android.DefaultsModuleBase
}

func defaultsFactory() android.Module {
	return DefaultsFactory()
}

func DefaultsFactory(props ...interface{}) android.Module {
	module := &Defaults{}

	module.AddProperties(props...)
	module.AddProperties(&BpfProperties{})

	android.InitDefaultsModule(module)

	return module
}

func (bpf *bpf) SubDir() string {
	return bpf.properties.Sub_dir
}

func BpfFactory() android.Module {
	module := &bpf{}

	module.AddProperties(&module.properties)

	android.InitAndroidArchModule(module, android.DeviceSupported, android.MultilibCommon)
	android.InitDefaultableModule(module)

	return module
}
