// Copyright 2017 Google Inc. All rights reserved.
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

package python

import (
	"fmt"

	"github.com/google/blueprint/proptools"

	"android/soong/android"
	"android/soong/tradefed"
)

// This file contains the module types for building Python test.

func init() {
	registerPythonTestComponents(android.InitRegistrationContext)
}

func registerPythonTestComponents(ctx android.RegistrationContext) {
	ctx.RegisterModuleType("python_test_host", PythonTestHostFactory)
	ctx.RegisterModuleType("python_test", PythonTestFactory)
}

func NewTest(hod android.HostOrDeviceSupported) *PythonTestModule {
	p := &PythonTestModule{PythonBinaryModule: *NewBinary(hod)}
	p.sourceProperties = android.SourceProperties{Test_only: proptools.BoolPtr(true), Top_level_test_target: true}
	return p
}

func PythonTestHostFactory() android.Module {
	return NewTest(android.HostSupported).init()
}

func PythonTestFactory() android.Module {
	module := NewTest(android.HostAndDeviceSupported)
	module.multilib = android.MultilibBoth
	return module.init()
}

type TestProperties struct {
	// the name of the test configuration (for example "AndroidTest.xml") that should be
	// installed with the module.
	Test_config *string `android:"path,arch_variant"`

	// the name of the test configuration template (for example "AndroidTestTemplate.xml") that
	// should be installed with the module.
	Test_config_template *string `android:"path,arch_variant"`

	// list of files or filegroup modules that provide data that should be installed alongside
	// the test
	Data []string `android:"path,arch_variant"`

	// Same as data, but will add dependencies on modules using the device's os variation and
	// the common arch variation. Useful for a host test that wants to embed a module built for
	// device.
	Device_common_data []string `android:"path_device_common"`

	// Same as data, but will add dependencies on modules via a device os variation and the
	// device's first supported arch's variation. Useful for a host test that wants to embed a
	// module built for device.
	Device_first_data []string `android:"path_device_first"`

	// list of java modules that provide data that should be installed alongside the test.
	Java_data []string

	// Test options.
	Test_options TestOptions

	// list of device binary modules that should be installed alongside the test
	// This property adds 64bit AND 32bit variants of the dependency
	Data_device_bins_both []string `android:"arch_variant"`
}

type TestOptions struct {
	android.CommonTestOptions

	// Runner for the test. Supports "tradefed" and "mobly" (for multi-device tests). Default is "tradefed".
	Runner *string

	// Metadata to describe the test configuration.
	Metadata []Metadata
}

type Metadata struct {
	Name  string
	Value string
}

type PythonTestModule struct {
	PythonBinaryModule

	testProperties TestProperties
	testConfig     android.Path
	data           []android.DataPath
}

func (p *PythonTestModule) init() android.Module {
	p.AddProperties(&p.properties, &p.protoProperties)
	p.AddProperties(&p.binaryProperties)
	p.AddProperties(&p.testProperties)
	android.InitAndroidArchModule(p, p.hod, p.multilib)
	android.InitDefaultableModule(p)
	if p.isTestHost() && p.testProperties.Test_options.Unit_test == nil {
		p.testProperties.Test_options.Unit_test = proptools.BoolPtr(true)
	}
	return p
}

func (p *PythonTestModule) isTestHost() bool {
	return p.hod == android.HostSupported
}

var dataDeviceBinsTag = dependencyTag{name: "dataDeviceBins"}

// python_test_host DepsMutator uses this method to add multilib dependencies of
// data_device_bin_both
func (p *PythonTestModule) addDataDeviceBinsDeps(ctx android.BottomUpMutatorContext, filter string) {
	if len(p.testProperties.Data_device_bins_both) < 1 {
		return
	}

	var maybeAndroidTarget *android.Target
	androidTargetList := android.FirstTarget(ctx.Config().Targets[android.Android], filter)
	if len(androidTargetList) > 0 {
		maybeAndroidTarget = &androidTargetList[0]
	}

	if maybeAndroidTarget != nil {
		ctx.AddFarVariationDependencies(
			maybeAndroidTarget.Variations(),
			dataDeviceBinsTag,
			p.testProperties.Data_device_bins_both...,
		)
	}
}

func (p *PythonTestModule) DepsMutator(ctx android.BottomUpMutatorContext) {
	p.PythonBinaryModule.DepsMutator(ctx)
	if p.isTestHost() {
		p.addDataDeviceBinsDeps(ctx, "lib32")
		p.addDataDeviceBinsDeps(ctx, "lib64")
	}
}

func (p *PythonTestModule) GenerateAndroidBuildActions(ctx android.ModuleContext) {
	// We inherit from only the library's GenerateAndroidBuildActions, and then
	// just use buildBinary() so that the binary is not installed into the location
	// it would be for regular binaries.
	p.PythonLibraryModule.GenerateAndroidBuildActions(ctx)
	p.buildBinary(ctx)

	var configs []tradefed.Option
	for _, metadata := range p.testProperties.Test_options.Metadata {
		configs = append(configs, tradefed.Option{Name: "config-descriptor:metadata", Key: metadata.Name, Value: metadata.Value})
	}

	runner := proptools.StringDefault(p.testProperties.Test_options.Runner, "tradefed")
	template := "${PythonBinaryHostTestConfigTemplate}"
	if runner == "mobly" {
		// Add tag to enable Atest mobly runner
		if !android.InList("mobly", p.testProperties.Test_options.Tags) {
			p.testProperties.Test_options.Tags = append(p.testProperties.Test_options.Tags, "mobly")
		}
		template = "${PythonBinaryHostMoblyTestConfigTemplate}"
	} else if runner != "tradefed" {
		panic(fmt.Errorf("unknown python test runner '%s', should be 'tradefed' or 'mobly'", runner))
	}
	p.testConfig = tradefed.AutoGenTestConfig(ctx, tradefed.AutoGenTestConfigOptions{
		TestConfigProp:          p.testProperties.Test_config,
		TestConfigTemplateProp:  p.testProperties.Test_config_template,
		TestSuites:              p.binaryProperties.Test_suites,
		OptionsForAutogenerated: configs,
		AutoGenConfig:           p.binaryProperties.Auto_gen_config,
		DeviceTemplate:          template,
		HostTemplate:            template,
	})

	for _, dataSrcPath := range android.PathsForModuleSrc(ctx, p.testProperties.Data) {
		p.data = append(p.data, android.DataPath{SrcPath: dataSrcPath})
	}
	for _, dataSrcPath := range android.PathsForModuleSrc(ctx, p.testProperties.Device_common_data) {
		p.data = append(p.data, android.DataPath{SrcPath: dataSrcPath})
	}
	for _, dataSrcPath := range android.PathsForModuleSrc(ctx, p.testProperties.Device_first_data) {
		p.data = append(p.data, android.DataPath{SrcPath: dataSrcPath})
	}

	if p.isTestHost() && len(p.testProperties.Data_device_bins_both) > 0 {
		ctx.VisitDirectDepsProxyWithTag(dataDeviceBinsTag, func(dep android.ModuleProxy) {
			p.data = append(p.data, android.DataPath{SrcPath: android.OutputFileForModule(ctx, dep, "")})
		})
	}

	// Emulate the data property for java_data dependencies.
	for _, javaData := range ctx.GetDirectDepsProxyWithTag(javaDataTag) {
		for _, javaDataSrcPath := range android.OutputFilesForModule(ctx, javaData, "") {
			p.data = append(p.data, android.DataPath{SrcPath: javaDataSrcPath})
		}
	}

	installDir := installDir(ctx, "nativetest", "nativetest64", ctx.ModuleName())
	installedData := ctx.InstallTestData(installDir, p.data)
	p.installedDest = ctx.InstallFile(installDir, p.installSource.Base(), p.installSource, installedData...)

	// TODO: Remove the special case for kati
	if !ctx.Config().KatiEnabled() {
		// Install the test config in testcases/ directory for atest.
		// Install configs in the root of $PRODUCT_OUT/testcases/$module
		testCases := android.PathForModuleInPartitionInstall(ctx, "testcases", ctx.ModuleName())
		if ctx.PrimaryArch() {
			if p.testConfig != nil {
				ctx.InstallFile(testCases, ctx.ModuleName()+".config", p.testConfig)
			}
			dynamicConfig := android.ExistentPathForSource(ctx, ctx.ModuleDir(), "DynamicConfig.xml")
			if dynamicConfig.Valid() {
				ctx.InstallFile(testCases, ctx.ModuleName()+".dynamic", dynamicConfig.Path())
			}
		}
		// Install tests and data in arch specific subdir $PRODUCT_OUT/testcases/$module/$arch
		testCases = testCases.Join(ctx, ctx.Target().Arch.ArchType.String())
		installedData := ctx.InstallTestData(testCases, p.data)
		ctx.InstallFile(testCases, p.installSource.Base(), p.installSource, installedData...)
	}

	moduleInfoJSON := ctx.ModuleInfoJSON()
	moduleInfoJSON.Class = []string{"NATIVE_TESTS"}
	if len(p.binaryProperties.Test_suites) > 0 {
		moduleInfoJSON.CompatibilitySuites = append(moduleInfoJSON.CompatibilitySuites, p.binaryProperties.Test_suites...)
	} else {
		moduleInfoJSON.CompatibilitySuites = append(moduleInfoJSON.CompatibilitySuites, "null-suite")
	}
	if p.testConfig != nil {
		moduleInfoJSON.TestConfig = append(moduleInfoJSON.TestConfig, p.testConfig.String())
	}
	if _, ok := p.testConfig.(android.WritablePath); ok {
		moduleInfoJSON.AutoTestConfig = []string{"true"}
	}
	moduleInfoJSON.TestOptionsTags = append(moduleInfoJSON.TestOptionsTags, p.testProperties.Test_options.Tags...)
	moduleInfoJSON.Dependencies = append(moduleInfoJSON.Dependencies, p.androidMkSharedLibs...)
	moduleInfoJSON.SharedLibs = append(moduleInfoJSON.Dependencies, p.androidMkSharedLibs...)
	moduleInfoJSON.SystemSharedLibs = []string{"none"}
	if proptools.Bool(p.testProperties.Test_options.Unit_test) {
		moduleInfoJSON.IsUnitTest = "true"
		if p.isTestHost() {
			moduleInfoJSON.CompatibilitySuites = append(moduleInfoJSON.CompatibilitySuites, "host-unit-tests")
		}
	}
}

func (p *PythonTestModule) AndroidMkEntries() []android.AndroidMkEntries {
	entriesList := p.PythonBinaryModule.AndroidMkEntries()
	if len(entriesList) != 1 {
		panic("Expected 1 entry")
	}
	entries := &entriesList[0]

	entries.Class = "NATIVE_TESTS"

	entries.ExtraEntries = append(entries.ExtraEntries,
		func(ctx android.AndroidMkExtraEntriesContext, entries *android.AndroidMkEntries) {
			//entries.AddCompatibilityTestSuites(p.binaryProperties.Test_suites...)
			if p.testConfig != nil {
				entries.SetString("LOCAL_FULL_TEST_CONFIG", p.testConfig.String())
			}

			// ATS 2.0 is the test harness for mobly tests and the test config is for ATS 2.0.
			// Add "v2" suffix to test config name to distinguish it from the config for TF.
			if proptools.String(p.testProperties.Test_options.Runner) == "mobly" {
				entries.SetString("LOCAL_TEST_CONFIG_SUFFIX", "v2")
			}

			entries.SetBoolIfTrue("LOCAL_DISABLE_AUTO_GENERATE_TEST_CONFIG", !BoolDefault(p.binaryProperties.Auto_gen_config, true))

			p.testProperties.Test_options.SetAndroidMkEntries(entries)
		})

	return entriesList
}
