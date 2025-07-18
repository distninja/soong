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

// This file offers AndroidMkEntriesProvider, which individual modules implement to output
// Android.mk entries that contain information about the modules built through Soong. Kati reads
// and combines them with the legacy Make-based module definitions to produce the complete view of
// the source tree, which makes this a critical point of Make-Soong interoperability.
//
// Naturally, Soong-only builds do not rely on this mechanism.

package android

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strconv"
	"strings"

	"github.com/google/blueprint"
	"github.com/google/blueprint/pathtools"
	"github.com/google/blueprint/proptools"
)

func init() {
	RegisterAndroidMkBuildComponents(InitRegistrationContext)
}

func RegisterAndroidMkBuildComponents(ctx RegistrationContext) {
	ctx.RegisterParallelSingletonType("androidmk", AndroidMkSingleton)
}

// Enable androidmk support.
// * Register the singleton
// * Configure that we are inside make
var PrepareForTestWithAndroidMk = GroupFixturePreparers(
	FixtureRegisterWithContext(RegisterAndroidMkBuildComponents),
	FixtureModifyConfig(SetKatiEnabledForTests),
)

// Deprecated: Use AndroidMkEntriesProvider instead, especially if you're not going to use the
// Custom function. It's easier to use and test.
type AndroidMkDataProvider interface {
	AndroidMk() AndroidMkData
	BaseModuleName() string
}

type AndroidMkData struct {
	Class           string
	SubName         string
	OutputFile      OptionalPath
	Disabled        bool
	Include         string
	Required        []string
	Host_required   []string
	Target_required []string

	Custom func(w io.Writer, name, prefix, moduleDir string, data AndroidMkData)

	Extra []AndroidMkExtraFunc

	Entries AndroidMkEntries
}

type AndroidMkDataInfo struct {
	Class string
}

var AndroidMkDataInfoProvider = blueprint.NewProvider[AndroidMkDataInfo]()

type AndroidMkExtraFunc func(w io.Writer, outputFile Path)

// Interface for modules to declare their Android.mk outputs. Note that every module needs to
// implement this in order to be included in the final Android-<product_name>.mk output, even if
// they only need to output the common set of entries without any customizations.
type AndroidMkEntriesProvider interface {
	// Returns AndroidMkEntries objects that contain all basic info plus extra customization data
	// if needed. This is the core func to implement.
	// Note that one can return multiple objects. For example, java_library may return an additional
	// AndroidMkEntries object for its hostdex sub-module.
	AndroidMkEntries() []AndroidMkEntries
	// Modules don't need to implement this as it's already implemented by ModuleBase.
	// AndroidMkEntries uses BaseModuleName() instead of ModuleName() because certain modules
	// e.g. Prebuilts, override the Name() func and return modified names.
	// If a different name is preferred, use SubName or OverrideName in AndroidMkEntries.
	BaseModuleName() string
}

// The core data struct that modules use to provide their Android.mk data.
type AndroidMkEntries struct {
	// Android.mk class string, e.g EXECUTABLES, JAVA_LIBRARIES, ETC
	Class string
	// Optional suffix to append to the module name. Useful when a module wants to return multiple
	// AndroidMkEntries objects. For example, when a java_library returns an additional entry for
	// its hostdex sub-module, this SubName field is set to "-hostdex" so that it can have a
	// different name than the parent's.
	SubName string
	// If set, this value overrides the base module name. SubName is still appended.
	OverrideName string
	// The output file for Kati to process and/or install. If absent, the module is skipped.
	OutputFile OptionalPath
	// If true, the module is skipped and does not appear on the final Android-<product name>.mk
	// file. Useful when a module needs to be skipped conditionally.
	Disabled bool
	// The postprocessing mk file to include, e.g. $(BUILD_SYSTEM)/soong_cc_rust_prebuilt.mk
	// If not set, $(BUILD_SYSTEM)/prebuilt.mk is used.
	Include string
	// Required modules that need to be built and included in the final build output when building
	// this module.
	Required []string
	// Required host modules that need to be built and included in the final build output when
	// building this module.
	Host_required []string
	// Required device modules that need to be built and included in the final build output when
	// building this module.
	Target_required []string

	header bytes.Buffer
	footer bytes.Buffer

	// Funcs to append additional Android.mk entries or modify the common ones. Multiple funcs are
	// accepted so that common logic can be factored out as a shared func.
	ExtraEntries []AndroidMkExtraEntriesFunc
	// Funcs to add extra lines to the module's Android.mk output. Unlike AndroidMkExtraEntriesFunc,
	// which simply sets Make variable values, this can be used for anything since it can write any
	// Make statements directly to the final Android-*.mk file.
	// Primarily used to call macros or declare/update Make targets.
	ExtraFooters []AndroidMkExtraFootersFunc

	// A map that holds the up-to-date Make variable values. Can be accessed from tests.
	EntryMap map[string][]string
	// A list of EntryMap keys in insertion order. This serves a few purposes:
	// 1. Prevents churns. Golang map doesn't provide consistent iteration order, so without this,
	// the outputted Android-*.mk file may change even though there have been no content changes.
	// 2. Allows modules to refer to other variables, like LOCAL_BAR_VAR := $(LOCAL_FOO_VAR),
	// without worrying about the variables being mixed up in the actual mk file.
	// 3. Makes troubleshooting and spotting errors easier.
	entryOrder []string

	// Provides data typically stored by Context objects that are commonly needed by
	//AndroidMkEntries objects.
	entryContext AndroidMkEntriesContext
}

type AndroidMkEntriesContext interface {
	OtherModuleProviderContext
	Config() Config
}

type AndroidMkExtraEntriesContext interface {
	Provider(provider blueprint.AnyProviderKey) (any, bool)
}

type androidMkExtraEntriesContext struct {
	ctx fillInEntriesContext
	mod Module
}

func (a *androidMkExtraEntriesContext) Provider(provider blueprint.AnyProviderKey) (any, bool) {
	return a.ctx.otherModuleProvider(a.mod, provider)
}

type AndroidMkExtraEntriesFunc func(ctx AndroidMkExtraEntriesContext, entries *AndroidMkEntries)
type AndroidMkExtraFootersFunc func(w io.Writer, name, prefix, moduleDir string)

// Utility funcs to manipulate Android.mk variable entries.

// SetString sets a Make variable with the given name to the given value.
func (a *AndroidMkEntries) SetString(name, value string) {
	if _, ok := a.EntryMap[name]; !ok {
		a.entryOrder = append(a.entryOrder, name)
	}
	a.EntryMap[name] = []string{value}
}

// SetPath sets a Make variable with the given name to the given path string.
func (a *AndroidMkEntries) SetPath(name string, path Path) {
	if _, ok := a.EntryMap[name]; !ok {
		a.entryOrder = append(a.entryOrder, name)
	}
	a.EntryMap[name] = []string{path.String()}
}

// SetOptionalPath sets a Make variable with the given name to the given path string if it is valid.
// It is a no-op if the given path is invalid.
func (a *AndroidMkEntries) SetOptionalPath(name string, path OptionalPath) {
	if path.Valid() {
		a.SetPath(name, path.Path())
	}
}

// AddPath appends the given path string to a Make variable with the given name.
func (a *AndroidMkEntries) AddPath(name string, path Path) {
	if _, ok := a.EntryMap[name]; !ok {
		a.entryOrder = append(a.entryOrder, name)
	}
	a.EntryMap[name] = append(a.EntryMap[name], path.String())
}

// AddOptionalPath appends the given path string to a Make variable with the given name if it is
// valid. It is a no-op if the given path is invalid.
func (a *AndroidMkEntries) AddOptionalPath(name string, path OptionalPath) {
	if path.Valid() {
		a.AddPath(name, path.Path())
	}
}

// SetPaths sets a Make variable with the given name to a slice of the given path strings.
func (a *AndroidMkEntries) SetPaths(name string, paths Paths) {
	if _, ok := a.EntryMap[name]; !ok {
		a.entryOrder = append(a.entryOrder, name)
	}
	a.EntryMap[name] = paths.Strings()
}

// SetOptionalPaths sets a Make variable with the given name to a slice of the given path strings
// only if there are a non-zero amount of paths.
func (a *AndroidMkEntries) SetOptionalPaths(name string, paths Paths) {
	if len(paths) > 0 {
		a.SetPaths(name, paths)
	}
}

// AddPaths appends the given path strings to a Make variable with the given name.
func (a *AndroidMkEntries) AddPaths(name string, paths Paths) {
	if _, ok := a.EntryMap[name]; !ok {
		a.entryOrder = append(a.entryOrder, name)
	}
	a.EntryMap[name] = append(a.EntryMap[name], paths.Strings()...)
}

// SetBoolIfTrue sets a Make variable with the given name to true if the given flag is true.
// It is a no-op if the given flag is false.
func (a *AndroidMkEntries) SetBoolIfTrue(name string, flag bool) {
	if flag {
		if _, ok := a.EntryMap[name]; !ok {
			a.entryOrder = append(a.entryOrder, name)
		}
		a.EntryMap[name] = []string{"true"}
	}
}

// SetBool sets a Make variable with the given name to if the given bool flag value.
func (a *AndroidMkEntries) SetBool(name string, flag bool) {
	if _, ok := a.EntryMap[name]; !ok {
		a.entryOrder = append(a.entryOrder, name)
	}
	if flag {
		a.EntryMap[name] = []string{"true"}
	} else {
		a.EntryMap[name] = []string{"false"}
	}
}

// AddStrings appends the given strings to a Make variable with the given name.
func (a *AndroidMkEntries) AddStrings(name string, value ...string) {
	if len(value) == 0 {
		return
	}
	if _, ok := a.EntryMap[name]; !ok {
		a.entryOrder = append(a.entryOrder, name)
	}
	a.EntryMap[name] = append(a.EntryMap[name], value...)
}

// AddCompatibilityTestSuites adds the supplied test suites to the EntryMap, with special handling
// for partial MTS and MCTS test suites.
func (a *AndroidMkEntries) AddCompatibilityTestSuites(suites ...string) {
	// M(C)TS supports a full test suite and partial per-module MTS test suites, with naming mts-${MODULE}.
	// To reduce repetition, if we find a partial M(C)TS test suite without an full M(C)TS test suite,
	// we add the full test suite to our list.
	if PrefixInList(suites, "mts-") && !InList("mts", suites) {
		suites = append(suites, "mts")
	}
	if PrefixInList(suites, "mcts-") && !InList("mcts", suites) {
		suites = append(suites, "mcts")
	}
	a.AddStrings("LOCAL_COMPATIBILITY_SUITE", suites...)
}

// The contributions to the dist.
type distContributions struct {
	// Path to license metadata file.
	licenseMetadataFile Path
	// List of goals and the dist copy instructions.
	copiesForGoals []*copiesForGoals
}

// getCopiesForGoals returns a copiesForGoals into which copy instructions that
// must be processed when building one or more of those goals can be added.
func (d *distContributions) getCopiesForGoals(goals string) *copiesForGoals {
	copiesForGoals := &copiesForGoals{goals: goals}
	d.copiesForGoals = append(d.copiesForGoals, copiesForGoals)
	return copiesForGoals
}

// Associates a list of dist copy instructions with a set of goals for which they
// should be run.
type copiesForGoals struct {
	// goals are a space separated list of build targets that will trigger the
	// copy instructions.
	goals string

	// A list of instructions to copy a module's output files to somewhere in the
	// dist directory.
	copies []distCopy
}

// Adds a copy instruction.
func (d *copiesForGoals) addCopyInstruction(from Path, dest string) {
	d.copies = append(d.copies, distCopy{from, dest})
}

// Instruction on a path that must be copied into the dist.
type distCopy struct {
	// The path to copy from.
	from Path

	// The destination within the dist directory to copy to.
	dest string
}

func (d *distCopy) String() string {
	if len(d.dest) == 0 {
		return d.from.String()
	}
	return fmt.Sprintf("%s:%s", d.from.String(), d.dest)
}

type distCopies []distCopy

func (d *distCopies) Strings() (ret []string) {
	if d == nil {
		return
	}
	for _, dist := range *d {
		ret = append(ret, dist.String())
	}
	return
}

// This gets the dist contributuions from the given module that were specified in the Android.bp
// file using the dist: property. It does not include contribututions that the module's
// implementation may have defined with ctx.DistForGoals(), for that, see DistProvider.
func getDistContributions(ctx ConfigAndOtherModuleProviderContext, mod Module) *distContributions {
	amod := mod.base()
	name := amod.BaseModuleName()

	info := OtherModuleProviderOrDefault(ctx, mod, InstallFilesProvider)
	availableTaggedDists := info.DistFiles

	if len(availableTaggedDists) == 0 {
		// Nothing dist-able for this module.
		return nil
	}

	// Collate the contributions this module makes to the dist.
	distContributions := &distContributions{}

	if !exemptFromRequiredApplicableLicensesProperty(mod) {
		distContributions.licenseMetadataFile = info.LicenseMetadataFile
	}

	// Iterate over this module's dist structs, merged from the dist and dists properties.
	for _, dist := range amod.Dists() {
		// Get the list of goals this dist should be enabled for. e.g. sdk, droidcore
		goals := strings.Join(dist.Targets, " ")

		// Get the tag representing the output files to be dist'd. e.g. ".jar", ".proguard_map"
		var tag string
		if dist.Tag == nil {
			// If the dist struct does not specify a tag, use the default output files tag.
			tag = DefaultDistTag
		} else {
			tag = *dist.Tag
		}

		// Get the paths of the output files to be dist'd, represented by the tag.
		// Can be an empty list.
		tagPaths := availableTaggedDists[tag]
		if len(tagPaths) == 0 {
			// Nothing to dist for this tag, continue to the next dist.
			continue
		}

		if len(tagPaths) > 1 && (dist.Dest != nil || dist.Suffix != nil) {
			errorMessage := "%s: Cannot apply dest/suffix for more than one dist " +
				"file for %q goals tag %q in module %s. The list of dist files, " +
				"which should have a single element, is:\n%s"
			panic(fmt.Errorf(errorMessage, mod, goals, tag, name, tagPaths))
		}

		copiesForGoals := distContributions.getCopiesForGoals(goals)

		// Iterate over each path adding a copy instruction to copiesForGoals
		for _, path := range tagPaths {
			// It's possible that the Path is nil from errant modules. Be defensive here.
			if path == nil {
				tagName := "default" // for error message readability
				if dist.Tag != nil {
					tagName = *dist.Tag
				}
				panic(fmt.Errorf("Dist file should not be nil for the %s tag in %s", tagName, name))
			}

			dest := filepath.Base(path.String())

			if dist.Dest != nil {
				var err error
				if dest, err = validateSafePath(*dist.Dest); err != nil {
					// This was checked in ModuleBase.GenerateBuildActions
					panic(err)
				}
			}

			ext := filepath.Ext(dest)
			suffix := ""
			if dist.Suffix != nil {
				suffix = *dist.Suffix
			}

			prependProductString := ""
			if proptools.Bool(dist.Prepend_artifact_with_product) {
				prependProductString = fmt.Sprintf("%s-", ctx.Config().DeviceProduct())
			}

			appendProductString := ""
			if proptools.Bool(dist.Append_artifact_with_product) {
				appendProductString = fmt.Sprintf("_%s", ctx.Config().DeviceProduct())
			}

			if suffix != "" || appendProductString != "" || prependProductString != "" {
				dest = prependProductString + strings.TrimSuffix(dest, ext) + suffix + appendProductString + ext
			}

			if dist.Dir != nil {
				var err error
				if dest, err = validateSafePath(*dist.Dir, dest); err != nil {
					// This was checked in ModuleBase.GenerateBuildActions
					panic(err)
				}
			}

			copiesForGoals.addCopyInstruction(path, dest)
		}
	}

	return distContributions
}

// generateDistContributionsForMake generates make rules that will generate the
// dist according to the instructions in the supplied distContribution.
func generateDistContributionsForMake(distContributions *distContributions) []string {
	var ret []string
	for _, d := range distContributions.copiesForGoals {
		ret = append(ret, fmt.Sprintf(".PHONY: %s", d.goals))
		// Create dist-for-goals calls for each of the copy instructions.
		for _, c := range d.copies {
			if distContributions.licenseMetadataFile != nil {
				ret = append(
					ret,
					fmt.Sprintf("$(if $(strip $(ALL_TARGETS.%s.META_LIC)),,$(eval ALL_TARGETS.%s.META_LIC := %s))",
						c.from.String(), c.from.String(), distContributions.licenseMetadataFile.String()))
			}
			ret = append(
				ret,
				fmt.Sprintf("$(call dist-for-goals,%s,%s:%s)", d.goals, c.from.String(), c.dest))
		}
	}

	return ret
}

// Compute the list of Make strings to declare phony goals and dist-for-goals
// calls from the module's dist and dists properties.
func (a *AndroidMkEntries) GetDistForGoals(mod Module) []string {
	distContributions := getDistContributions(a.entryContext, mod)
	if distContributions == nil {
		return nil
	}

	return generateDistContributionsForMake(distContributions)
}

// fillInEntries goes through the common variable processing and calls the extra data funcs to
// generate and fill in AndroidMkEntries's in-struct data, ready to be flushed to a file.
type fillInEntriesContext interface {
	ModuleDir(module blueprint.Module) string
	ModuleSubDir(module blueprint.Module) string
	Config() Config
	otherModuleProvider(module blueprint.Module, provider blueprint.AnyProviderKey) (any, bool)
	ModuleType(module blueprint.Module) string
	OtherModulePropertyErrorf(module Module, property string, fmt string, args ...interface{})
	HasMutatorFinished(mutatorName string) bool
}

func (a *AndroidMkEntries) fillInEntries(ctx fillInEntriesContext, mod Module) {
	a.entryContext = ctx
	a.EntryMap = make(map[string][]string)
	base := mod.base()
	name := base.BaseModuleName()
	if bmn, ok := mod.(baseModuleName); ok {
		name = bmn.BaseModuleName()
	}
	if a.OverrideName != "" {
		name = a.OverrideName
	}

	if a.Include == "" {
		a.Include = "$(BUILD_PREBUILT)"
	}
	a.Required = append(a.Required, mod.RequiredModuleNames(ctx)...)
	a.Required = append(a.Required, mod.VintfFragmentModuleNames(ctx)...)
	a.Host_required = append(a.Host_required, mod.HostRequiredModuleNames()...)
	a.Target_required = append(a.Target_required, mod.TargetRequiredModuleNames()...)

	for _, distString := range a.GetDistForGoals(mod) {
		fmt.Fprintln(&a.header, distString)
	}

	fmt.Fprintf(&a.header, "\ninclude $(CLEAR_VARS)  # type: %s, name: %s, variant: %s\n", ctx.ModuleType(mod), base.BaseModuleName(), ctx.ModuleSubDir(mod))

	// Add the TestSuites from the provider to LOCAL_SOONG_PROVIDER_TEST_SUITES.
	// LOCAL_SOONG_PROVIDER_TEST_SUITES will be compared against LOCAL_COMPATIBILITY_SUITES
	// in make and enforced they're the same, to ensure we've successfully translated all
	// LOCAL_COMPATIBILITY_SUITES usages to the provider.
	if testSuiteInfo, ok := OtherModuleProvider(ctx, mod, TestSuiteInfoProvider); ok {
		a.AddStrings("LOCAL_SOONG_PROVIDER_TEST_SUITES", testSuiteInfo.TestSuites...)
	}

	// Collect make variable assignment entries.
	a.SetString("LOCAL_PATH", ctx.ModuleDir(mod))
	a.SetString("LOCAL_MODULE", name+a.SubName)
	a.SetString("LOCAL_MODULE_CLASS", a.Class)
	a.SetString("LOCAL_PREBUILT_MODULE_FILE", a.OutputFile.String())
	a.AddStrings("LOCAL_REQUIRED_MODULES", a.Required...)
	a.AddStrings("LOCAL_HOST_REQUIRED_MODULES", a.Host_required...)
	a.AddStrings("LOCAL_TARGET_REQUIRED_MODULES", a.Target_required...)
	a.AddStrings("LOCAL_SOONG_MODULE_TYPE", ctx.ModuleType(mod))

	// If the install rule was generated by Soong tell Make about it.
	info := OtherModuleProviderOrDefault(ctx, mod, InstallFilesProvider)
	if len(info.KatiInstalls) > 0 {
		// Assume the primary install file is last since it probably needs to depend on any other
		// installed files.  If that is not the case we can add a method to specify the primary
		// installed file.
		a.SetPath("LOCAL_SOONG_INSTALLED_MODULE", info.KatiInstalls[len(info.KatiInstalls)-1].to)
		a.SetString("LOCAL_SOONG_INSTALL_PAIRS", info.KatiInstalls.BuiltInstalled())
		a.SetPaths("LOCAL_SOONG_INSTALL_SYMLINKS", info.KatiSymlinks.InstallPaths().Paths())
	} else {
		// Soong may not have generated the install rule also when `no_full_install: true`.
		// Mark this module as uninstallable in order to prevent Make from creating an
		// install rule there.
		a.SetBoolIfTrue("LOCAL_UNINSTALLABLE_MODULE", proptools.Bool(base.commonProperties.No_full_install))
	}

	if info.UncheckedModule {
		a.SetBool("LOCAL_DONT_CHECK_MODULE", true)
	} else if info.CheckbuildTarget != nil {
		a.SetPath("LOCAL_CHECKED_MODULE", info.CheckbuildTarget)
	} else {
		a.SetOptionalPath("LOCAL_CHECKED_MODULE", a.OutputFile)
	}

	if len(info.TestData) > 0 {
		a.AddStrings("LOCAL_TEST_DATA", androidMkDataPaths(info.TestData)...)
	}

	if am, ok := mod.(ApexModule); ok {
		a.SetBoolIfTrue("LOCAL_NOT_AVAILABLE_FOR_PLATFORM", am.NotAvailableForPlatform())
	}

	archStr := base.Arch().ArchType.String()
	host := false
	switch base.Os().Class {
	case Host:
		if base.Target().HostCross {
			// Make cannot identify LOCAL_MODULE_HOST_CROSS_ARCH:= common.
			if base.Arch().ArchType != Common {
				a.SetString("LOCAL_MODULE_HOST_CROSS_ARCH", archStr)
			}
		} else {
			// Make cannot identify LOCAL_MODULE_HOST_ARCH:= common.
			if base.Arch().ArchType != Common {
				a.SetString("LOCAL_MODULE_HOST_ARCH", archStr)
			}
		}
		host = true
	case Device:
		// Make cannot identify LOCAL_MODULE_TARGET_ARCH:= common.
		if base.Arch().ArchType != Common {
			if base.Target().NativeBridge {
				hostArchStr := base.Target().NativeBridgeHostArchName
				if hostArchStr != "" {
					a.SetString("LOCAL_MODULE_TARGET_ARCH", hostArchStr)
				}
			} else {
				a.SetString("LOCAL_MODULE_TARGET_ARCH", archStr)
			}
		}

		if !base.InVendorRamdisk() {
			a.AddPaths("LOCAL_FULL_INIT_RC", info.InitRcPaths)
		}
		if len(info.VintfFragmentsPaths) > 0 {
			a.AddPaths("LOCAL_FULL_VINTF_FRAGMENTS", info.VintfFragmentsPaths)
		}
		a.SetBoolIfTrue("LOCAL_PROPRIETARY_MODULE", Bool(base.commonProperties.Proprietary))
		if Bool(base.commonProperties.Vendor) || Bool(base.commonProperties.Soc_specific) {
			a.SetString("LOCAL_VENDOR_MODULE", "true")
		}
		a.SetBoolIfTrue("LOCAL_ODM_MODULE", Bool(base.commonProperties.Device_specific))
		a.SetBoolIfTrue("LOCAL_PRODUCT_MODULE", Bool(base.commonProperties.Product_specific))
		a.SetBoolIfTrue("LOCAL_SYSTEM_EXT_MODULE", Bool(base.commonProperties.System_ext_specific))
		if base.commonProperties.Owner != nil {
			a.SetString("LOCAL_MODULE_OWNER", *base.commonProperties.Owner)
		}
	}

	if host {
		makeOs := base.Os().String()
		if base.Os() == Linux || base.Os() == LinuxBionic || base.Os() == LinuxMusl {
			makeOs = "linux"
		}
		a.SetString("LOCAL_MODULE_HOST_OS", makeOs)
		a.SetString("LOCAL_IS_HOST_MODULE", "true")
	}

	prefix := ""
	if base.ArchSpecific() {
		switch base.Os().Class {
		case Host:
			if base.Target().HostCross {
				prefix = "HOST_CROSS_"
			} else {
				prefix = "HOST_"
			}
		case Device:
			prefix = "TARGET_"

		}

		if base.Arch().ArchType != ctx.Config().Targets[base.Os()][0].Arch.ArchType {
			prefix = "2ND_" + prefix
		}
	}

	if licenseMetadata, ok := OtherModuleProvider(ctx, mod, LicenseMetadataProvider); ok {
		a.SetPath("LOCAL_SOONG_LICENSE_METADATA", licenseMetadata.LicenseMetadataPath)
	}

	if _, ok := OtherModuleProvider(ctx, mod, ModuleInfoJSONProvider); ok {
		a.SetBool("LOCAL_SOONG_MODULE_INFO_JSON", true)
	}

	extraCtx := &androidMkExtraEntriesContext{
		ctx: ctx,
		mod: mod,
	}

	for _, extra := range a.ExtraEntries {
		extra(extraCtx, a)
	}

	// Write to footer.
	fmt.Fprintln(&a.footer, "include "+a.Include)
	blueprintDir := ctx.ModuleDir(mod)
	for _, footerFunc := range a.ExtraFooters {
		footerFunc(&a.footer, name, prefix, blueprintDir)
	}
}

func (a *AndroidMkEntries) disabled() bool {
	return a.Disabled || !a.OutputFile.Valid()
}

// write  flushes the AndroidMkEntries's in-struct data populated by AndroidMkEntries into the
// given Writer object.
func (a *AndroidMkEntries) write(w io.Writer) {
	if a.disabled() {
		return
	}

	w.Write(a.header.Bytes())
	for _, name := range a.entryOrder {
		AndroidMkEmitAssignList(w, name, a.EntryMap[name])
	}
	w.Write(a.footer.Bytes())
}

func (a *AndroidMkEntries) FooterLinesForTests() []string {
	return strings.Split(string(a.footer.Bytes()), "\n")
}

// AndroidMkSingleton is a singleton to collect Android.mk data from all modules and dump them into
// the final Android-<product_name>.mk file output.
func AndroidMkSingleton() Singleton {
	return &androidMkSingleton{}
}

type androidMkSingleton struct{}

func allModulesSorted(ctx SingletonContext) []Module {
	var allModules []Module

	ctx.VisitAllModules(func(module Module) {
		allModules = append(allModules, module)
	})

	// Sort the module list by the module names to eliminate random churns, which may erroneously
	// invoke additional build processes.
	sort.SliceStable(allModules, func(i, j int) bool {
		return ctx.ModuleName(allModules[i]) < ctx.ModuleName(allModules[j])
	})

	return allModules
}

func (c *androidMkSingleton) GenerateBuildActions(ctx SingletonContext) {
	// If running in soong-only mode, more limited version of this singleton is run as
	// soong only androidmk singleton
	if !ctx.Config().KatiEnabled() {
		return
	}

	transMk := PathForOutput(ctx, "Android"+String(ctx.Config().productVariables.Make_suffix)+".mk")
	if ctx.Failed() {
		return
	}

	moduleInfoJSON := PathForOutput(ctx, "module-info"+String(ctx.Config().productVariables.Make_suffix)+".json")

	err := translateAndroidMk(ctx, absolutePath(transMk.String()), moduleInfoJSON, allModulesSorted(ctx))
	if err != nil {
		ctx.Errorf(err.Error())
	}

	ctx.Build(pctx, BuildParams{
		Rule:   blueprint.Phony,
		Output: transMk,
	})
}

type soongOnlyAndroidMkSingleton struct {
	Singleton
}

func soongOnlyAndroidMkSingletonFactory() Singleton {
	return &soongOnlyAndroidMkSingleton{}
}

func (so *soongOnlyAndroidMkSingleton) GenerateBuildActions(ctx SingletonContext) {
	if !ctx.Config().KatiEnabled() {
		so.soongOnlyBuildActions(ctx, allModulesSorted(ctx))
	}
}

// In soong-only mode, we don't do most of the androidmk stuff. But disted files are still largely
// defined through the androidmk mechanisms, so this function is an alternate implementation of
// the androidmk singleton that just focuses on getting the dist contributions
// TODO(b/397766191): Change the signature to take ModuleProxy
// Please only access the module's internal data through providers.
func (so *soongOnlyAndroidMkSingleton) soongOnlyBuildActions(ctx SingletonContext, mods []Module) {
	allDistContributions, moduleInfoJSONs := getSoongOnlyDataFromMods(ctx, mods)

	singletonDists := getSingletonDists(ctx.Config())
	singletonDists.lock.Lock()
	if contribution := distsToDistContributions(singletonDists.dists); contribution != nil {
		allDistContributions = append(allDistContributions, *contribution)
	}
	singletonDists.lock.Unlock()

	// Build module-info.json. Only in builds with HasDeviceProduct(), as we need a named
	// device to have a TARGET_OUT folder.
	if ctx.Config().HasDeviceProduct() {
		preMergePath := PathForOutput(ctx, "module_info_pre_merging.json")
		moduleInfoJSONPath := pathForInstall(ctx, Android, X86_64, "", "module-info.json")
		if err := writeModuleInfoJSON(ctx, moduleInfoJSONs, preMergePath); err != nil {
			ctx.Errorf("%s", err)
		}
		builder := NewRuleBuilder(pctx, ctx)
		builder.Command().
			BuiltTool("merge_module_info_json").
			FlagWithOutput("-o ", moduleInfoJSONPath).
			Input(preMergePath)
		builder.Build("merge_module_info_json", "merge module info json")
		ctx.Phony("module-info", moduleInfoJSONPath)
		ctx.Phony("droidcore-unbundled", moduleInfoJSONPath)
		allDistContributions = append(allDistContributions, distContributions{
			copiesForGoals: []*copiesForGoals{{
				goals: "general-tests droidcore-unbundled",
				copies: []distCopy{{
					from: moduleInfoJSONPath,
					dest: "module-info.json",
				}},
			}},
		})
	}

	// Build dist.mk for the packaging step to read and generate dist targets
	distMkFile := absolutePath(filepath.Join(ctx.Config().katiPackageMkDir(), "dist.mk"))

	var goalOutputPairs []string
	var srcDstPairs []string
	for _, contributions := range allDistContributions {
		for _, copiesForGoal := range contributions.copiesForGoals {
			goals := strings.Fields(copiesForGoal.goals)
			for _, copy := range copiesForGoal.copies {
				for _, goal := range goals {
					goalOutputPairs = append(goalOutputPairs, fmt.Sprintf(" %s:%s", goal, copy.dest))
				}
				srcDstPairs = append(srcDstPairs, fmt.Sprintf(" %s:%s", copy.from.String(), copy.dest))
			}
		}
	}
	// There are duplicates in the lists that we need to remove
	goalOutputPairs = SortedUniqueStrings(goalOutputPairs)
	srcDstPairs = SortedUniqueStrings(srcDstPairs)
	var buf strings.Builder
	buf.WriteString("DIST_SRC_DST_PAIRS :=")
	for _, srcDstPair := range srcDstPairs {
		buf.WriteString(srcDstPair)
	}
	buf.WriteString("\nDIST_GOAL_OUTPUT_PAIRS :=")
	for _, goalOutputPair := range goalOutputPairs {
		buf.WriteString(goalOutputPair)
	}
	buf.WriteString("\n")

	writeValueIfChanged(ctx, distMkFile, buf.String())
}

func writeValueIfChanged(ctx SingletonContext, path string, value string) {
	if err := os.MkdirAll(filepath.Dir(path), 0777); err != nil {
		ctx.Errorf("%s\n", err)
		return
	}
	previousValue := ""
	rawPreviousValue, err := os.ReadFile(path)
	if err == nil {
		previousValue = string(rawPreviousValue)
	}

	if previousValue != value {
		if err = os.WriteFile(path, []byte(value), 0666); err != nil {
			ctx.Errorf("Failed to write: %v", err)
		}
	}
}

func distsToDistContributions(dists []dist) *distContributions {
	if len(dists) == 0 {
		return nil
	}

	copyGoals := []*copiesForGoals{}
	for _, dist := range dists {
		for _, goal := range dist.goals {
			copyGoals = append(copyGoals, &copiesForGoals{
				goals:  goal,
				copies: dist.paths,
			})
		}
	}

	return &distContributions{
		copiesForGoals: copyGoals,
	}
}

// getSoongOnlyDataFromMods gathers data from the given modules needed in soong-only builds.
// Currently, this is the dist contributions, and the module-info.json contents.
func getSoongOnlyDataFromMods(ctx fillInEntriesContext, mods []Module) ([]distContributions, []*ModuleInfoJSON) {
	var allDistContributions []distContributions
	var moduleInfoJSONs []*ModuleInfoJSON
	for _, mod := range mods {
		if distInfo, ok := OtherModuleProvider(ctx, mod, DistProvider); ok {
			if contribution := distsToDistContributions(distInfo.Dists); contribution != nil {
				allDistContributions = append(allDistContributions, *contribution)
			}
		}

		commonInfo := OtherModulePointerProviderOrDefault(ctx, mod, CommonModuleInfoProvider)
		if commonInfo.SkipAndroidMkProcessing {
			continue
		}
		if info, ok := OtherModuleProvider(ctx, mod, AndroidMkInfoProvider); ok {
			// Deep copy the provider info since we need to modify the info later
			info := deepCopyAndroidMkProviderInfo(info)
			info.PrimaryInfo.fillInEntries(ctx, mod, commonInfo)
			if info.PrimaryInfo.disabled() {
				continue
			}
			if moduleInfoJSON, ok := OtherModuleProvider(ctx, mod, ModuleInfoJSONProvider); ok {
				moduleInfoJSONs = append(moduleInfoJSONs, moduleInfoJSON...)
			}
			if contribution := getDistContributions(ctx, mod); contribution != nil {
				allDistContributions = append(allDistContributions, *contribution)
			}
		} else {
			if x, ok := mod.(AndroidMkDataProvider); ok {
				data := x.AndroidMk()

				if data.Include == "" {
					data.Include = "$(BUILD_PREBUILT)"
				}

				data.fillInData(ctx, mod)
				if data.Entries.disabled() {
					continue
				}
				if moduleInfoJSON, ok := OtherModuleProvider(ctx, mod, ModuleInfoJSONProvider); ok {
					moduleInfoJSONs = append(moduleInfoJSONs, moduleInfoJSON...)
				}
				if contribution := getDistContributions(ctx, mod); contribution != nil {
					allDistContributions = append(allDistContributions, *contribution)
				}
			}
			if x, ok := mod.(AndroidMkEntriesProvider); ok {
				entriesList := x.AndroidMkEntries()
				for _, entries := range entriesList {
					entries.fillInEntries(ctx, mod)
					if entries.disabled() {
						continue
					}
					if moduleInfoJSON, ok := OtherModuleProvider(ctx, mod, ModuleInfoJSONProvider); ok {
						moduleInfoJSONs = append(moduleInfoJSONs, moduleInfoJSON...)
					}
					if contribution := getDistContributions(ctx, mod); contribution != nil {
						allDistContributions = append(allDistContributions, *contribution)
					}
				}
			}
		}
	}
	return allDistContributions, moduleInfoJSONs
}

func translateAndroidMk(ctx SingletonContext, absMkFile string, moduleInfoJSONPath WritablePath, mods []Module) error {
	buf := &bytes.Buffer{}

	var moduleInfoJSONs []*ModuleInfoJSON

	fmt.Fprintln(buf, "LOCAL_MODULE_MAKEFILE := $(lastword $(MAKEFILE_LIST))")

	typeStats := make(map[string]int)
	for _, mod := range mods {
		err := translateAndroidMkModule(ctx, buf, &moduleInfoJSONs, mod)
		if err != nil {
			os.Remove(absMkFile)
			return err
		}

		if ctx.PrimaryModule(mod) == mod {
			typeStats[ctx.ModuleType(mod)] += 1
		}
	}

	keys := []string{}
	fmt.Fprintln(buf, "\nSTATS.SOONG_MODULE_TYPE :=")
	for k := range typeStats {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, mod_type := range keys {
		fmt.Fprintln(buf, "STATS.SOONG_MODULE_TYPE +=", mod_type)
		fmt.Fprintf(buf, "STATS.SOONG_MODULE_TYPE.%s := %d\n", mod_type, typeStats[mod_type])
	}

	err := pathtools.WriteFileIfChanged(absMkFile, buf.Bytes(), 0666)
	if err != nil {
		return err
	}

	return writeModuleInfoJSON(ctx, moduleInfoJSONs, moduleInfoJSONPath)
}

func writeModuleInfoJSON(ctx SingletonContext, moduleInfoJSONs []*ModuleInfoJSON, moduleInfoJSONPath WritablePath) error {
	moduleInfoJSONBuf := &strings.Builder{}
	moduleInfoJSONBuf.WriteString("[")
	for i, moduleInfoJSON := range moduleInfoJSONs {
		if i != 0 {
			moduleInfoJSONBuf.WriteString(",\n")
		}
		moduleInfoJSONBuf.WriteString("{")
		moduleInfoJSONBuf.WriteString(strconv.Quote(moduleInfoJSON.core.RegisterName))
		moduleInfoJSONBuf.WriteString(":")
		err := encodeModuleInfoJSON(moduleInfoJSONBuf, moduleInfoJSON)
		moduleInfoJSONBuf.WriteString("}")
		if err != nil {
			return err
		}
	}
	moduleInfoJSONBuf.WriteString("]")
	WriteFileRule(ctx, moduleInfoJSONPath, moduleInfoJSONBuf.String())
	return nil
}

func translateAndroidMkModule(ctx SingletonContext, w io.Writer, moduleInfoJSONs *[]*ModuleInfoJSON, mod Module) error {
	defer func() {
		if r := recover(); r != nil {
			panic(fmt.Errorf("%s in translateAndroidMkModule for module %s variant %s",
				r, ctx.ModuleName(mod), ctx.ModuleSubDir(mod)))
		}
	}()

	// Additional cases here require review for correct license propagation to make.
	var err error

	if info, ok := OtherModuleProvider(ctx, mod, AndroidMkInfoProvider); ok {
		err = translateAndroidMkEntriesInfoModule(ctx, w, moduleInfoJSONs, mod, info)
	} else {
		switch x := mod.(type) {
		case AndroidMkDataProvider:
			err = translateAndroidModule(ctx, w, moduleInfoJSONs, mod, x)
		case AndroidMkEntriesProvider:
			err = translateAndroidMkEntriesModule(ctx, w, moduleInfoJSONs, mod, x)
		default:
			// Not exported to make so no make variables to set.
		}
	}

	if err != nil {
		return err
	}

	return err
}

func (data *AndroidMkData) fillInData(ctx fillInEntriesContext, mod Module) {
	// Get the preamble content through AndroidMkEntries logic.
	data.Entries = AndroidMkEntries{
		Class:           data.Class,
		SubName:         data.SubName,
		OutputFile:      data.OutputFile,
		Disabled:        data.Disabled,
		Include:         data.Include,
		Required:        data.Required,
		Host_required:   data.Host_required,
		Target_required: data.Target_required,
	}
	data.Entries.fillInEntries(ctx, mod)

	// copy entries back to data since it is used in Custom
	data.Required = data.Entries.Required
	data.Host_required = data.Entries.Host_required
	data.Target_required = data.Entries.Target_required
}

// A support func for the deprecated AndroidMkDataProvider interface. Use AndroidMkEntryProvider
// instead.
func translateAndroidModule(ctx SingletonContext, w io.Writer, moduleInfoJSONs *[]*ModuleInfoJSON,
	mod Module, provider AndroidMkDataProvider) error {

	amod := mod.base()
	if shouldSkipAndroidMkProcessing(ctx, amod) {
		return nil
	}

	data := provider.AndroidMk()

	if data.Include == "" {
		data.Include = "$(BUILD_PREBUILT)"
	}

	data.fillInData(ctx, mod)
	aconfigUpdateAndroidMkData(ctx, mod, &data)

	prefix := ""
	if amod.ArchSpecific() {
		switch amod.Os().Class {
		case Host:
			if amod.Target().HostCross {
				prefix = "HOST_CROSS_"
			} else {
				prefix = "HOST_"
			}
		case Device:
			prefix = "TARGET_"

		}

		if amod.Arch().ArchType != ctx.Config().Targets[amod.Os()][0].Arch.ArchType {
			prefix = "2ND_" + prefix
		}
	}

	name := provider.BaseModuleName()
	blueprintDir := filepath.Dir(ctx.BlueprintFile(mod))

	if data.Custom != nil {
		// List of module types allowed to use .Custom(...)
		// Additions to the list require careful review for proper license handling.
		switch reflect.TypeOf(mod).String() { // ctx.ModuleType(mod) doesn't work: aidl_interface creates phony without type
		case "*aidl.aidlApi": // writes non-custom before adding .phony
		case "*aidl.aidlMapping": // writes non-custom before adding .phony
		case "*android.customModule": // appears in tests only
		case "*android_sdk.sdkRepoHost": // doesn't go through base_rules
		case "*apex.apexBundle": // license properties written
		case "*bpf.bpf": // license properties written (both for module and objs)
		case "*libbpf_prog.libbpfProg": // license properties written (both for module and objs)
		case "*genrule.Module": // writes non-custom before adding .phony
		case "*java.SystemModules": // doesn't go through base_rules
		case "*java.systemModulesImport": // doesn't go through base_rules
		case "*phony.phony": // license properties written
		case "*phony.PhonyRule": // writes phony deps and acts like `.PHONY`
		case "*selinux.selinuxContextsModule": // license properties written
		case "*sysprop.syspropLibrary": // license properties written
		case "*vintf.vintfCompatibilityMatrixRule": // use case like phony
		default:
			if !ctx.Config().IsEnvFalse("ANDROID_REQUIRE_LICENSES") {
				return fmt.Errorf("custom make rules not allowed for %q (%q) module %q", ctx.ModuleType(mod), reflect.TypeOf(mod), ctx.ModuleName(mod))
			}
		}
		data.Custom(w, name, prefix, blueprintDir, data)
	} else {
		WriteAndroidMkData(w, data)
	}

	if !data.Entries.disabled() {
		if moduleInfoJSON, ok := OtherModuleProvider(ctx, mod, ModuleInfoJSONProvider); ok {
			*moduleInfoJSONs = append(*moduleInfoJSONs, moduleInfoJSON...)
		}
	}

	return nil
}

// A support func for the deprecated AndroidMkDataProvider interface. Use AndroidMkEntryProvider
// instead.
func WriteAndroidMkData(w io.Writer, data AndroidMkData) {
	if data.Entries.disabled() {
		return
	}

	// write preamble via Entries
	data.Entries.footer = bytes.Buffer{}
	data.Entries.write(w)

	for _, extra := range data.Extra {
		extra(w, data.OutputFile.Path())
	}

	fmt.Fprintln(w, "include "+data.Include)
}

func translateAndroidMkEntriesModule(ctx SingletonContext, w io.Writer, moduleInfoJSONs *[]*ModuleInfoJSON,
	mod Module, provider AndroidMkEntriesProvider) error {
	if shouldSkipAndroidMkProcessing(ctx, mod.base()) {
		return nil
	}

	entriesList := provider.AndroidMkEntries()
	aconfigUpdateAndroidMkEntries(ctx, mod, &entriesList)

	moduleInfoJSON, providesModuleInfoJSON := OtherModuleProvider(ctx, mod, ModuleInfoJSONProvider)

	// Any new or special cases here need review to verify correct propagation of license information.
	for _, entries := range entriesList {
		entries.fillInEntries(ctx, mod)
		entries.write(w)

		if providesModuleInfoJSON && !entries.disabled() {
			// append only the name matching moduleInfoJSON entry
			for _, m := range moduleInfoJSON {
				if m.RegisterNameOverride == entries.OverrideName && m.SubName == entries.SubName {
					*moduleInfoJSONs = append(*moduleInfoJSONs, m)
				}
			}
		}
	}

	return nil
}

func ShouldSkipAndroidMkProcessing(ctx ConfigurableEvaluatorContext, module Module) bool {
	return shouldSkipAndroidMkProcessing(ctx, module.base())
}

func shouldSkipAndroidMkProcessing(ctx ConfigurableEvaluatorContext, module *ModuleBase) bool {
	if !module.commonProperties.NamespaceExportedToMake {
		// TODO(jeffrygaston) do we want to validate that there are no modules being
		// exported to Kati that depend on this module?
		return true
	}

	// On Mac, only expose host darwin modules to Make, as that's all we claim to support.
	// In reality, some of them depend on device-built (Java) modules, so we can't disable all
	// device modules in Soong, but we can hide them from Make (and thus the build user interface)
	if runtime.GOOS == "darwin" && module.Os() != Darwin {
		return true
	}

	// Only expose the primary Darwin target, as Make does not understand Darwin+Arm64
	if module.Os() == Darwin && module.Target().HostCross {
		return true
	}

	return !module.Enabled(ctx) ||
		module.commonProperties.HideFromMake ||
		// Make does not understand LinuxBionic
		module.Os() == LinuxBionic ||
		// Make does not understand LinuxMusl, except when we are building with USE_HOST_MUSL=true
		// and all host binaries are LinuxMusl
		(module.Os() == LinuxMusl && module.Target().HostCross)
}

// A utility func to format LOCAL_TEST_DATA outputs. See the comments on DataPath to understand how
// to use this func.
func androidMkDataPaths(data []DataPath) []string {
	var testFiles []string
	for _, d := range data {
		rel := d.SrcPath.Rel()
		if d.WithoutRel {
			rel = d.SrcPath.Base()
		}
		path := d.SrcPath.String()
		// LOCAL_TEST_DATA requires the rel portion of the path to be removed from the path.
		if !strings.HasSuffix(path, rel) {
			panic(fmt.Errorf("path %q does not end with %q", path, rel))
		}
		path = strings.TrimSuffix(path, rel)
		testFileString := path + ":" + rel
		if len(d.RelativeInstallPath) > 0 {
			testFileString += ":" + d.RelativeInstallPath
		}
		testFiles = append(testFiles, testFileString)
	}
	return testFiles
}

// AndroidMkEmitAssignList emits the line
//
//	VAR := ITEM ...
//
// Items are the elements to the given set of lists
// If all the passed lists are empty, no line will be emitted
func AndroidMkEmitAssignList(w io.Writer, varName string, lists ...[]string) {
	doPrint := false
	for _, l := range lists {
		if doPrint = len(l) > 0; doPrint {
			break
		}
	}
	if !doPrint {
		return
	}
	fmt.Fprint(w, varName, " :=")
	for _, l := range lists {
		for _, item := range l {
			fmt.Fprint(w, " ", item)
		}
	}
	fmt.Fprintln(w)
}

type AndroidMkProviderInfo struct {
	PrimaryInfo AndroidMkInfo
	ExtraInfo   []AndroidMkInfo
}

type AndroidMkInfo struct {
	// Android.mk class string, e.g. EXECUTABLES, JAVA_LIBRARIES, ETC
	Class string
	// Optional suffix to append to the module name. Useful when a module wants to return multiple
	// AndroidMkEntries objects. For example, when a java_library returns an additional entry for
	// its hostdex sub-module, this SubName field is set to "-hostdex" so that it can have a
	// different name than the parent's.
	SubName string
	// If set, this value overrides the base module name. SubName is still appended.
	OverrideName string
	// The output file for Kati to process and/or install. If absent, the module is skipped.
	OutputFile OptionalPath
	// If true, the module is skipped and does not appear on the final Android-<product name>.mk
	// file. Useful when a module needs to be skipped conditionally.
	Disabled bool
	// The postprocessing mk file to include, e.g. $(BUILD_SYSTEM)/soong_cc_rust_prebuilt.mk
	// If not set, $(BUILD_SYSTEM)/prebuilt.mk is used.
	Include string
	// Required modules that need to be built and included in the final build output when building
	// this module.
	Required []string
	// Required host modules that need to be built and included in the final build output when
	// building this module.
	Host_required []string
	// Required device modules that need to be built and included in the final build output when
	// building this module.
	Target_required []string

	HeaderStrings []string
	FooterStrings []string

	// A map that holds the up-to-date Make variable values. Can be accessed from tests.
	EntryMap map[string][]string
	// A list of EntryMap keys in insertion order. This serves a few purposes:
	// 1. Prevents churns. Golang map doesn't provide consistent iteration order, so without this,
	// the outputted Android-*.mk file may change even though there have been no content changes.
	// 2. Allows modules to refer to other variables, like LOCAL_BAR_VAR := $(LOCAL_FOO_VAR),
	// without worrying about the variables being mixed up in the actual mk file.
	// 3. Makes troubleshooting and spotting errors easier.
	EntryOrder []string
}

type AndroidMkProviderInfoProducer interface {
	PrepareAndroidMKProviderInfo(config Config) *AndroidMkProviderInfo
}

// TODO: rename it to AndroidMkEntriesProvider after AndroidMkEntriesProvider interface is gone.
var AndroidMkInfoProvider = blueprint.NewProvider[*AndroidMkProviderInfo]()

// TODO(b/397766191): Change the signature to take ModuleProxy
// Please only access the module's internal data through providers.
func translateAndroidMkEntriesInfoModule(ctx SingletonContext, w io.Writer, moduleInfoJSONs *[]*ModuleInfoJSON,
	mod Module, providerInfo *AndroidMkProviderInfo) error {
	commonInfo := OtherModulePointerProviderOrDefault(ctx, mod, CommonModuleInfoProvider)
	if commonInfo.SkipAndroidMkProcessing {
		return nil
	}

	// Deep copy the provider info since we need to modify the info later
	info := deepCopyAndroidMkProviderInfo(providerInfo)

	aconfigUpdateAndroidMkInfos(ctx, mod, &info)

	// Any new or special cases here need review to verify correct propagation of license information.
	info.PrimaryInfo.fillInEntries(ctx, mod, commonInfo)
	info.PrimaryInfo.write(w)
	if len(info.ExtraInfo) > 0 {
		for _, ei := range info.ExtraInfo {
			ei.fillInEntries(ctx, mod, commonInfo)
			ei.write(w)
		}
	}

	if !info.PrimaryInfo.disabled() {
		if moduleInfoJSON, ok := OtherModuleProvider(ctx, mod, ModuleInfoJSONProvider); ok {
			*moduleInfoJSONs = append(*moduleInfoJSONs, moduleInfoJSON...)
		}
	}

	return nil
}

// Utility funcs to manipulate Android.mk variable entries.

// SetString sets a Make variable with the given name to the given value.
func (a *AndroidMkInfo) SetString(name, value string) {
	if _, ok := a.EntryMap[name]; !ok {
		a.EntryOrder = append(a.EntryOrder, name)
	}
	a.EntryMap[name] = []string{value}
}

// SetPath sets a Make variable with the given name to the given path string.
func (a *AndroidMkInfo) SetPath(name string, path Path) {
	if _, ok := a.EntryMap[name]; !ok {
		a.EntryOrder = append(a.EntryOrder, name)
	}
	a.EntryMap[name] = []string{path.String()}
}

// SetOptionalPath sets a Make variable with the given name to the given path string if it is valid.
// It is a no-op if the given path is invalid.
func (a *AndroidMkInfo) SetOptionalPath(name string, path OptionalPath) {
	if path.Valid() {
		a.SetPath(name, path.Path())
	}
}

// AddPath appends the given path string to a Make variable with the given name.
func (a *AndroidMkInfo) AddPath(name string, path Path) {
	if _, ok := a.EntryMap[name]; !ok {
		a.EntryOrder = append(a.EntryOrder, name)
	}
	a.EntryMap[name] = append(a.EntryMap[name], path.String())
}

// AddOptionalPath appends the given path string to a Make variable with the given name if it is
// valid. It is a no-op if the given path is invalid.
func (a *AndroidMkInfo) AddOptionalPath(name string, path OptionalPath) {
	if path.Valid() {
		a.AddPath(name, path.Path())
	}
}

// SetPaths sets a Make variable with the given name to a slice of the given path strings.
func (a *AndroidMkInfo) SetPaths(name string, paths Paths) {
	if _, ok := a.EntryMap[name]; !ok {
		a.EntryOrder = append(a.EntryOrder, name)
	}
	a.EntryMap[name] = paths.Strings()
}

// SetOptionalPaths sets a Make variable with the given name to a slice of the given path strings
// only if there are a non-zero amount of paths.
func (a *AndroidMkInfo) SetOptionalPaths(name string, paths Paths) {
	if len(paths) > 0 {
		a.SetPaths(name, paths)
	}
}

// AddPaths appends the given path strings to a Make variable with the given name.
func (a *AndroidMkInfo) AddPaths(name string, paths Paths) {
	if _, ok := a.EntryMap[name]; !ok {
		a.EntryOrder = append(a.EntryOrder, name)
	}
	a.EntryMap[name] = append(a.EntryMap[name], paths.Strings()...)
}

// SetBoolIfTrue sets a Make variable with the given name to true if the given flag is true.
// It is a no-op if the given flag is false.
func (a *AndroidMkInfo) SetBoolIfTrue(name string, flag bool) {
	if flag {
		if _, ok := a.EntryMap[name]; !ok {
			a.EntryOrder = append(a.EntryOrder, name)
		}
		a.EntryMap[name] = []string{"true"}
	}
}

// SetBool sets a Make variable with the given name to if the given bool flag value.
func (a *AndroidMkInfo) SetBool(name string, flag bool) {
	if _, ok := a.EntryMap[name]; !ok {
		a.EntryOrder = append(a.EntryOrder, name)
	}
	if flag {
		a.EntryMap[name] = []string{"true"}
	} else {
		a.EntryMap[name] = []string{"false"}
	}
}

// AddStrings appends the given strings to a Make variable with the given name.
func (a *AndroidMkInfo) AddStrings(name string, value ...string) {
	if len(value) == 0 {
		return
	}
	if _, ok := a.EntryMap[name]; !ok {
		a.EntryOrder = append(a.EntryOrder, name)
	}
	a.EntryMap[name] = append(a.EntryMap[name], value...)
}

// AddCompatibilityTestSuites adds the supplied test suites to the EntryMap, with special handling
// for partial MTS and MCTS test suites.
func (a *AndroidMkInfo) AddCompatibilityTestSuites(suites ...string) {
	// M(C)TS supports a full test suite and partial per-module MTS test suites, with naming mts-${MODULE}.
	// To reduce repetition, if we find a partial M(C)TS test suite without an full M(C)TS test suite,
	// we add the full test suite to our list.
	if PrefixInList(suites, "mts-") && !InList("mts", suites) {
		suites = append(suites, "mts")
	}
	if PrefixInList(suites, "mcts-") && !InList("mcts", suites) {
		suites = append(suites, "mcts")
	}
	a.AddStrings("LOCAL_COMPATIBILITY_SUITE", suites...)
}

// TODO(b/397766191): Change the signature to take ModuleProxy
// Please only access the module's internal data through providers.
func (a *AndroidMkInfo) fillInEntries(ctx fillInEntriesContext, mod Module, commonInfo *CommonModuleInfo) {
	helperInfo := AndroidMkInfo{
		EntryMap: make(map[string][]string),
	}

	name := commonInfo.BaseModuleName
	if a.OverrideName != "" {
		name = a.OverrideName
	}

	if a.Include == "" {
		a.Include = "$(BUILD_PREBUILT)"
	}
	a.Required = append(a.Required, commonInfo.RequiredModuleNames...)
	a.Required = append(a.Required, commonInfo.VintfFragmentModuleNames...)
	a.Host_required = append(a.Host_required, commonInfo.HostRequiredModuleNames...)
	a.Target_required = append(a.Target_required, commonInfo.TargetRequiredModuleNames...)

	a.HeaderStrings = append(a.HeaderStrings, a.GetDistForGoals(ctx, mod, commonInfo)...)
	a.HeaderStrings = append(a.HeaderStrings, fmt.Sprintf("\ninclude $(CLEAR_VARS)  # type: %s, name: %s, variant: %s", ctx.ModuleType(mod), commonInfo.BaseModuleName, ctx.ModuleSubDir(mod)))

	// Add the TestSuites from the provider to LOCAL_SOONG_PROVIDER_TEST_SUITES.
	// LOCAL_SOONG_PROVIDER_TEST_SUITES will be compared against LOCAL_COMPATIBILITY_SUITES
	// in make and enforced they're the same, to ensure we've successfully translated all
	// LOCAL_COMPATIBILITY_SUITES usages to the provider.
	if testSuiteInfo, ok := OtherModuleProvider(ctx, mod, TestSuiteInfoProvider); ok {
		helperInfo.AddStrings("LOCAL_SOONG_PROVIDER_TEST_SUITES", testSuiteInfo.TestSuites...)
	}

	// Collect make variable assignment entries.
	helperInfo.SetString("LOCAL_PATH", ctx.ModuleDir(mod))
	helperInfo.SetString("LOCAL_MODULE", name+a.SubName)
	helperInfo.SetString("LOCAL_MODULE_CLASS", a.Class)
	helperInfo.SetString("LOCAL_PREBUILT_MODULE_FILE", a.OutputFile.String())
	helperInfo.AddStrings("LOCAL_REQUIRED_MODULES", a.Required...)
	helperInfo.AddStrings("LOCAL_HOST_REQUIRED_MODULES", a.Host_required...)
	helperInfo.AddStrings("LOCAL_TARGET_REQUIRED_MODULES", a.Target_required...)
	helperInfo.AddStrings("LOCAL_SOONG_MODULE_TYPE", ctx.ModuleType(mod))

	// If the install rule was generated by Soong tell Make about it.
	info := OtherModuleProviderOrDefault(ctx, mod, InstallFilesProvider)
	if len(info.KatiInstalls) > 0 {
		// Assume the primary install file is last since it probably needs to depend on any other
		// installed files.  If that is not the case we can add a method to specify the primary
		// installed file.
		helperInfo.SetPath("LOCAL_SOONG_INSTALLED_MODULE", info.KatiInstalls[len(info.KatiInstalls)-1].to)
		helperInfo.SetString("LOCAL_SOONG_INSTALL_PAIRS", info.KatiInstalls.BuiltInstalled())
		helperInfo.SetPaths("LOCAL_SOONG_INSTALL_SYMLINKS", info.KatiSymlinks.InstallPaths().Paths())
	} else {
		// Soong may not have generated the install rule also when `no_full_install: true`.
		// Mark this module as uninstallable in order to prevent Make from creating an
		// install rule there.
		helperInfo.SetBoolIfTrue("LOCAL_UNINSTALLABLE_MODULE", commonInfo.NoFullInstall)
	}

	if info.UncheckedModule {
		helperInfo.SetBool("LOCAL_DONT_CHECK_MODULE", true)
	} else if info.CheckbuildTarget != nil {
		helperInfo.SetPath("LOCAL_CHECKED_MODULE", info.CheckbuildTarget)
	} else {
		helperInfo.SetOptionalPath("LOCAL_CHECKED_MODULE", a.OutputFile)
	}

	if len(info.TestData) > 0 {
		helperInfo.AddStrings("LOCAL_TEST_DATA", androidMkDataPaths(info.TestData)...)
	}

	if commonInfo.IsApexModule {
		helperInfo.SetBoolIfTrue("LOCAL_NOT_AVAILABLE_FOR_PLATFORM", commonInfo.NotAvailableForPlatform)
	}

	archStr := commonInfo.Target.Arch.ArchType.String()
	host := false
	switch commonInfo.Target.Os.Class {
	case Host:
		if commonInfo.Target.HostCross {
			// Make cannot identify LOCAL_MODULE_HOST_CROSS_ARCH:= common.
			if commonInfo.Target.Arch.ArchType != Common {
				helperInfo.SetString("LOCAL_MODULE_HOST_CROSS_ARCH", archStr)
			}
		} else {
			// Make cannot identify LOCAL_MODULE_HOST_ARCH:= common.
			if commonInfo.Target.Arch.ArchType != Common {
				helperInfo.SetString("LOCAL_MODULE_HOST_ARCH", archStr)
			}
		}
		host = true
	case Device:
		// Make cannot identify LOCAL_MODULE_TARGET_ARCH:= common.
		if commonInfo.Target.Arch.ArchType != Common {
			if commonInfo.Target.NativeBridge {
				hostArchStr := commonInfo.Target.NativeBridgeHostArchName
				if hostArchStr != "" {
					helperInfo.SetString("LOCAL_MODULE_TARGET_ARCH", hostArchStr)
				}
			} else {
				helperInfo.SetString("LOCAL_MODULE_TARGET_ARCH", archStr)
			}
		}

		if !commonInfo.InVendorRamdisk {
			helperInfo.AddPaths("LOCAL_FULL_INIT_RC", info.InitRcPaths)
		}
		if len(info.VintfFragmentsPaths) > 0 {
			helperInfo.AddPaths("LOCAL_FULL_VINTF_FRAGMENTS", info.VintfFragmentsPaths)
		}
		helperInfo.SetBoolIfTrue("LOCAL_PROPRIETARY_MODULE", commonInfo.Proprietary)
		if commonInfo.Vendor || commonInfo.SocSpecific {
			helperInfo.SetString("LOCAL_VENDOR_MODULE", "true")
		}
		helperInfo.SetBoolIfTrue("LOCAL_ODM_MODULE", commonInfo.DeviceSpecific)
		helperInfo.SetBoolIfTrue("LOCAL_PRODUCT_MODULE", commonInfo.ProductSpecific)
		helperInfo.SetBoolIfTrue("LOCAL_SYSTEM_EXT_MODULE", commonInfo.SystemExtSpecific)
		if commonInfo.Owner != "" {
			helperInfo.SetString("LOCAL_MODULE_OWNER", commonInfo.Owner)
		}
	}

	if host {
		os := commonInfo.Target.Os
		makeOs := os.String()
		if os == Linux || os == LinuxBionic || os == LinuxMusl {
			makeOs = "linux"
		}
		helperInfo.SetString("LOCAL_MODULE_HOST_OS", makeOs)
		helperInfo.SetString("LOCAL_IS_HOST_MODULE", "true")
	}

	if licenseMetadata, ok := OtherModuleProvider(ctx, mod, LicenseMetadataProvider); ok {
		helperInfo.SetPath("LOCAL_SOONG_LICENSE_METADATA", licenseMetadata.LicenseMetadataPath)
	}

	if _, ok := OtherModuleProvider(ctx, mod, ModuleInfoJSONProvider); ok {
		helperInfo.SetBool("LOCAL_SOONG_MODULE_INFO_JSON", true)
	}

	a.mergeEntries(&helperInfo)

	// Write to footer.
	a.FooterStrings = append([]string{"include " + a.Include}, a.FooterStrings...)
}

// This method merges the entries to helperInfo, then replaces a's EntryMap and
// EntryOrder with helperInfo's
func (a *AndroidMkInfo) mergeEntries(helperInfo *AndroidMkInfo) {
	for _, extraEntry := range a.EntryOrder {
		if v, ok := helperInfo.EntryMap[extraEntry]; ok {
			v = append(v, a.EntryMap[extraEntry]...)
		} else {
			helperInfo.EntryMap[extraEntry] = a.EntryMap[extraEntry]
			helperInfo.EntryOrder = append(helperInfo.EntryOrder, extraEntry)
		}
	}
	a.EntryOrder = helperInfo.EntryOrder
	a.EntryMap = helperInfo.EntryMap
}

func (a *AndroidMkInfo) disabled() bool {
	return a.Disabled || !a.OutputFile.Valid()
}

// write  flushes the AndroidMkEntries's in-struct data populated by AndroidMkEntries into the
// given Writer object.
func (a *AndroidMkInfo) write(w io.Writer) {
	if a.disabled() {
		return
	}

	combinedHeaderString := strings.Join(a.HeaderStrings, "\n") + "\n"
	combinedFooterString := strings.Join(a.FooterStrings, "\n") + "\n"
	w.Write([]byte(combinedHeaderString))
	for _, name := range a.EntryOrder {
		AndroidMkEmitAssignList(w, name, a.EntryMap[name])
	}
	w.Write([]byte(combinedFooterString))
}

// Compute the list of Make strings to declare phony goals and dist-for-goals
// calls from the module's dist and dists properties.
// TODO(b/397766191): Change the signature to take ModuleProxy
// Please only access the module's internal data through providers.
func (a *AndroidMkInfo) GetDistForGoals(ctx fillInEntriesContext, mod Module, commonInfo *CommonModuleInfo) []string {
	distContributions := getDistContributions(ctx, mod)
	if distContributions == nil {
		return nil
	}

	return generateDistContributionsForMake(distContributions)
}

func deepCopyAndroidMkProviderInfo(providerInfo *AndroidMkProviderInfo) AndroidMkProviderInfo {
	info := AndroidMkProviderInfo{
		PrimaryInfo: deepCopyAndroidMkInfo(&providerInfo.PrimaryInfo),
	}
	if len(providerInfo.ExtraInfo) > 0 {
		for _, i := range providerInfo.ExtraInfo {
			info.ExtraInfo = append(info.ExtraInfo, deepCopyAndroidMkInfo(&i))
		}
	}
	return info
}

func deepCopyAndroidMkInfo(mkinfo *AndroidMkInfo) AndroidMkInfo {
	info := AndroidMkInfo{
		Class:        mkinfo.Class,
		SubName:      mkinfo.SubName,
		OverrideName: mkinfo.OverrideName,
		// There is no modification on OutputFile, so no need to
		// make their deep copy.
		OutputFile:      mkinfo.OutputFile,
		Disabled:        mkinfo.Disabled,
		Include:         mkinfo.Include,
		Required:        deepCopyStringSlice(mkinfo.Required),
		Host_required:   deepCopyStringSlice(mkinfo.Host_required),
		Target_required: deepCopyStringSlice(mkinfo.Target_required),
		HeaderStrings:   deepCopyStringSlice(mkinfo.HeaderStrings),
		FooterStrings:   deepCopyStringSlice(mkinfo.FooterStrings),
		EntryOrder:      deepCopyStringSlice(mkinfo.EntryOrder),
	}
	info.EntryMap = make(map[string][]string)
	for k, v := range mkinfo.EntryMap {
		info.EntryMap[k] = deepCopyStringSlice(v)
	}

	return info
}

func deepCopyStringSlice(original []string) []string {
	result := make([]string, len(original))
	copy(result, original)
	return result
}
