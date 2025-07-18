// Copyright 2019 The Android Open Source Project
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

package config

import (
	"fmt"
	"strings"

	"android/soong/android"
	_ "android/soong/cc/config"
)

var (
	pctx = android.NewPackageContext("android/soong/rust/config")

	RustDefaultVersion = "1.83.0"
	RustDefaultBase    = "prebuilts/rust/"
	DefaultEdition     = "2021"
	Stdlibs            = []string{
		"libstd",
	}

	// Mapping between Soong internal arch types and std::env constants.
	// Required as Rust uses aarch64 when Soong uses arm64.
	StdEnvArch = map[android.ArchType]string{
		android.Arm:    "arm",
		android.Arm64:  "aarch64",
		android.X86:    "x86",
		android.X86_64: "x86_64",
	}

	GlobalRustFlags = []string{
		// Allow `--extern force:foo` for dylib support
		"-Z unstable-options",
		"-Z stack-protector=strong",
		"-Z remap-cwd-prefix=.",
		"-C debuginfo=2",
		"-C opt-level=3",
		"-C relocation-model=pic",
		"-C overflow-checks=on",
		"-C force-unwind-tables=yes",
		// Use v0 mangling to distinguish from C++ symbols
		"-C symbol-mangling-version=v0",
		"--color=always",
		"-Z dylib-lto",
		"-Z link-native-libraries=no",

		// cfg flag to indicate that we are building in AOSP with Soong
		"--cfg soong",
	}

	LinuxHostGlobalLinkFlags = []string{
		"-lc",
		"-lrt",
		"-ldl",
		"-lpthread",
		"-lm",
		"-lgcc_s",
		"-Wl,--compress-debug-sections=zstd",
	}

	deviceGlobalRustFlags = []string{
		"-C panic=abort",
		// Generate additional debug info for AutoFDO
		"-Z debug-info-for-profiling",
		// Android has ELF TLS on platform
		"-Z tls-model=global-dynamic",
	}

	deviceGlobalLinkFlags = []string{
		// Prepend the lld flags from cc_config so we stay in sync with cc
		"${cc_config.DeviceGlobalLldflags}",

		// Override cc's --no-undefined-version to allow rustc's generated alloc functions
		"-Wl,--undefined-version",

		"-Wl,-Bdynamic",
		"-nostdlib",
		"-Wl,--pack-dyn-relocs=android+relr",
		"-Wl,--use-android-relr-tags",
		"-Wl,--no-undefined",
		"-B${cc_config.ClangBin}",
		"-Wl,--compress-debug-sections=zstd",
	}
)

func RustPath(ctx android.PathContext) string {
	// I can't see any way to flatten the static variable inside Soong, so this
	// reproduces the init logic.
	var RustBase string = RustDefaultBase
	if override := ctx.Config().Getenv("RUST_PREBUILTS_BASE"); override != "" {
		RustBase = override
	}
	return fmt.Sprintf("%s/%s/%s", RustBase, HostPrebuiltTag(ctx.Config()), GetRustVersion(ctx))
}

func init() {
	pctx.SourcePathVariable("RustDefaultBase", RustDefaultBase)
	pctx.VariableConfigMethod("HostPrebuiltTag", HostPrebuiltTag)

	pctx.VariableFunc("RustBase", func(ctx android.PackageVarContext) string {
		if override := ctx.Config().Getenv("RUST_PREBUILTS_BASE"); override != "" {
			return override
		}
		return "${RustDefaultBase}"
	})

	pctx.VariableFunc("RustVersion", getRustVersionPctx)

	pctx.StaticVariable("RustPath", "${RustBase}/${HostPrebuiltTag}/${RustVersion}")
	pctx.StaticVariable("RustBin", "${RustPath}/bin")

	pctx.ImportAs("cc_config", "android/soong/cc/config")
	pctx.StaticVariable("ClangCmd", "${cc_config.ClangBin}/clang++")

	pctx.StaticVariable("DeviceGlobalLinkFlags", strings.Join(deviceGlobalLinkFlags, " "))

	pctx.StaticVariable("RUST_DEFAULT_VERSION", RustDefaultVersion)
	pctx.StaticVariable("GLOBAL_RUSTC_FLAGS", strings.Join(GlobalRustFlags, " "))
	pctx.StaticVariable("LINUX_HOST_GLOBAL_LINK_FLAGS", strings.Join(LinuxHostGlobalLinkFlags, " "))

	pctx.StaticVariable("DEVICE_GLOBAL_RUSTC_FLAGS", strings.Join(deviceGlobalRustFlags, " "))
	pctx.StaticVariable("DEVICE_GLOBAL_LINK_FLAGS",
		strings.Join(android.RemoveListFromList(deviceGlobalLinkFlags, []string{
			// The cc_config flags are retrieved from cc_toolchain by rust rules.
			"${cc_config.DeviceGlobalLldflags}",
			"-B${cc_config.ClangBin}",
		}), " "))
}

func HostPrebuiltTag(config android.Config) string {
	if config.UseHostMusl() {
		return "linux-musl-x86"
	} else {
		return config.PrebuiltOS()
	}
}

func getRustVersionPctx(ctx android.PackageVarContext) string {
	return GetRustVersion(ctx)
}

func GetRustVersion(ctx android.PathContext) string {
	if override := ctx.Config().Getenv("RUST_PREBUILTS_VERSION"); override != "" {
		return override
	}
	return RustDefaultVersion
}
