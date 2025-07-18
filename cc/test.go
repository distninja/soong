// Copyright 2016 Google Inc. All rights reserved.
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

import (
	"path/filepath"
	"strconv"

	"github.com/google/blueprint/depset"
	"github.com/google/blueprint/proptools"

	"android/soong/android"
	"android/soong/tradefed"
)

// TestLinkerProperties properties to be registered via the linker
type TestLinkerProperties struct {
	// if set, build against the gtest library. Defaults to true.
	Gtest *bool

	// if set, use the isolated gtest runner. Defaults to false.
	// Isolation is not supported on Windows.
	Isolated *bool
}

// TestInstallerProperties properties to be registered via the installer
type TestInstallerProperties struct {
	// list of compatibility suites (for example "cts", "vts") that the module should be installed into.
	Test_suites []string `android:"arch_variant"`
}

// Test option struct.
type TestOptions struct {
	android.CommonTestOptions

	// The UID that you want to run the test as on a device.
	Run_test_as *string

	// A list of free-formed strings without spaces that categorize the test.
	Test_suite_tag []string

	// a list of extra test configuration files that should be installed with the module.
	Extra_test_configs []string `android:"path,arch_variant"`

	// Add ShippingApiLevelModuleController to auto generated test config. If the device properties
	// for the shipping api level is less than the min_shipping_api_level, skip this module.
	Min_shipping_api_level *int64

	// Add ShippingApiLevelModuleController to auto generated test config. If any of the device
	// shipping api level and vendor api level properties are less than the
	// vsr_min_shipping_api_level, skip this module.
	// As this includes the shipping api level check, it is not allowed to define
	// min_shipping_api_level at the same time with this property.
	Vsr_min_shipping_api_level *int64

	// Add MinApiLevelModuleController with ro.vndk.version property. If ro.vndk.version has an
	// integer value and the value is less than the min_vndk_version, skip this module.
	Min_vndk_version *int64

	// Extra <option> tags to add to the auto generated test xml file under the test runner, e.g., GTest.
	// The "key" is optional in each of these.
	Test_runner_options []tradefed.Option
}

type TestBinaryProperties struct {
	// Disables the creation of a test-specific directory when used with
	// relative_install_path. Useful if several tests need to be in the same
	// directory.
	No_named_install_directory *bool

	// list of files or filegroup modules that provide data that should be installed alongside
	// the test
	Data []string `android:"path,arch_variant"`

	// Same as data, but adds dependencies on modules using the device's os variant, and common
	// architecture's variant. Can be useful to add device-built apps to the data of a host
	// test.
	Device_common_data []string `android:"path_device_common"`

	// Same as data, but adds dependencies on modules using the device's os variant, and the
	// device's first architecture's variant. Can be useful to add device-built apps to the data
	// of a host test.
	Device_first_data []string `android:"path_device_first"`

	// Same as data, but will add dependencies on modules using the host's os variation and
	// the common arch variation. Useful for a device test that wants to depend on a host
	// module, for example to include a custom Tradefed test runner.
	Host_common_data []string `android:"path_host_common"`

	// list of shared library modules that should be installed alongside the test
	Data_libs []string `android:"arch_variant"`

	// list of binary modules that should be installed alongside the test
	Data_bins []string `android:"arch_variant"`

	// the name of the test configuration (for example "AndroidTest.xml") that should be
	// installed with the module.
	Test_config *string `android:"path,arch_variant"`

	// the name of the test configuration template (for example "AndroidTestTemplate.xml") that
	// should be installed with the module.
	Test_config_template *string `android:"path,arch_variant"`

	// Test options.
	Test_options TestOptions

	// Add RootTargetPreparer to auto generated test config. This guarantees the test to run
	// with root permission.
	Require_root *bool

	// Add RunCommandTargetPreparer to stop framework before the test and start it after the test.
	Disable_framework *bool

	// Flag to indicate whether or not to create test config automatically. If AndroidTest.xml
	// doesn't exist next to the Android.bp, this attribute doesn't need to be set to true
	// explicitly.
	Auto_gen_config *bool

	// Add parameterized mainline modules to auto generated test config. The options will be
	// handled by TradeFed to download and install the specified modules on the device.
	Test_mainline_modules []string

	// Install the test into a folder named for the module in all test suites.
	Per_testcase_directory *bool

	// Install the test's dependencies into a folder named standalone-libs relative to the
	// test's installation path. ld-library-path will be set to this path in the test's
	// auto-generated config. This way the dependencies can be used by the test without having
	// to manually install them to the device. See more details in
	// go/standalone-native-device-tests.
	Standalone_test *bool
}

func init() {
	android.RegisterModuleType("cc_test", TestFactory)
	android.RegisterModuleType("cc_test_library", TestLibraryFactory)
	android.RegisterModuleType("cc_benchmark", BenchmarkFactory)
	android.RegisterModuleType("cc_test_host", TestHostFactory)
	android.RegisterModuleType("cc_benchmark_host", BenchmarkHostFactory)
}

// cc_test generates a test config file and an executable binary file to test
// specific functionality on a device. The executable binary gets an implicit
// static_libs dependency on libgtests unless the gtest flag is set to false.
func TestFactory() android.Module {
	module := NewTest(android.HostAndDeviceSupported)
	return module.Init()
}

// cc_test_library creates an archive of files (i.e. .o files) which is later
// referenced by another module (such as cc_test, cc_defaults or cc_test_library)
// for archiving or linking.
func TestLibraryFactory() android.Module {
	module := NewTestLibrary(android.HostAndDeviceSupported)
	return module.Init()
}

// cc_benchmark compiles an executable binary that performs benchmark testing
// of a specific component in a device. Additional files such as test suites
// and test configuration are installed on the side of the compiled executed
// binary.
func BenchmarkFactory() android.Module {
	module := NewBenchmark(android.HostAndDeviceSupported)
	module.testModule = true
	return module.Init()
}

// cc_test_host compiles a test host binary.
func TestHostFactory() android.Module {
	module := NewTest(android.HostSupported)
	return module.Init()
}

// cc_benchmark_host compiles an executable binary that performs benchmark
// testing of a specific component in the host. Additional files such as
// test suites and test configuration are installed on the side of the
// compiled executed binary.
func BenchmarkHostFactory() android.Module {
	module := NewBenchmark(android.HostSupported)
	return module.Init()
}

func (test *testBinary) dataPaths() []android.DataPath {
	return test.data
}

func (test *testBinary) testBinary() bool {
	return true
}

type testDecorator struct {
	LinkerProperties    TestLinkerProperties
	InstallerProperties TestInstallerProperties
	installer           *baseInstaller
	linker              *baseLinker
}

func (test *testDecorator) gtest() bool {
	return BoolDefault(test.LinkerProperties.Gtest, true)
}

func (test *testDecorator) isolated(ctx android.BaseModuleContext) bool {
	return BoolDefault(test.LinkerProperties.Isolated, false) && !ctx.Windows()
}

// NOTE: Keep this in sync with cc/cc_test.bzl#gtest_copts
func (test *testDecorator) linkerFlags(ctx ModuleContext, flags Flags) Flags {
	if !test.gtest() {
		return flags
	}

	flags.Local.CFlags = append(flags.Local.CFlags, "-DGTEST_HAS_STD_STRING")
	if ctx.Host() {
		flags.Local.CFlags = append(flags.Local.CFlags, "-O0", "-g")

		switch ctx.Os() {
		case android.Windows:
			flags.Local.CFlags = append(flags.Local.CFlags, "-DGTEST_OS_WINDOWS")
		case android.Linux:
			flags.Local.CFlags = append(flags.Local.CFlags, "-DGTEST_OS_LINUX")
		case android.Darwin:
			flags.Local.CFlags = append(flags.Local.CFlags, "-DGTEST_OS_MAC")
		}
	} else {
		flags.Local.CFlags = append(flags.Local.CFlags, "-DGTEST_OS_LINUX_ANDROID")
	}

	return flags
}

func (test *testDecorator) linkerDeps(ctx BaseModuleContext, deps Deps) Deps {
	if test.gtest() {
		if ctx.useSdk() && ctx.Device() {
			deps.StaticLibs = append(deps.StaticLibs, "libgtest_main_ndk_c++", "libgtest_ndk_c++")
		} else if test.isolated(ctx) {
			deps.StaticLibs = append(deps.StaticLibs, "libgtest_isolated_main")
			// The isolated library requires liblog, but adding it
			// as a static library means unit tests cannot override
			// liblog functions. Instead make it a shared library
			// dependency.
			deps.SharedLibs = append(deps.SharedLibs, "liblog")
		} else {
			deps.StaticLibs = append(deps.StaticLibs, "libgtest_main", "libgtest")
		}
	}

	return deps
}

func (test *testDecorator) linkerProps() []interface{} {
	return []interface{}{&test.LinkerProperties}
}

func (test *testDecorator) installerProps() []interface{} {
	return []interface{}{&test.InstallerProperties}
}

func (test *testDecorator) moduleInfoJSON(ctx android.ModuleContext, moduleInfoJSON *android.ModuleInfoJSON) {
	if android.PrefixInList(moduleInfoJSON.CompatibilitySuites, "mts-") &&
		!android.InList("mts", moduleInfoJSON.CompatibilitySuites) {
		moduleInfoJSON.CompatibilitySuites = append(moduleInfoJSON.CompatibilitySuites, "mts")
	}
}

func (test *testDecorator) testSuiteInfo(ctx ModuleContext) {
	android.SetProvider(ctx, android.TestSuiteInfoProvider, android.TestSuiteInfo{
		TestSuites: test.InstallerProperties.Test_suites,
	})
}

func NewTestInstaller() *baseInstaller {
	return NewBaseInstaller("nativetest", "nativetest64", InstallInData)
}

type testBinary struct {
	*testDecorator
	*binaryDecorator
	*baseCompiler
	Properties       TestBinaryProperties
	data             []android.DataPath
	testConfig       android.Path
	extraTestConfigs android.Paths
}

func (test *testBinary) linkerProps() []interface{} {
	props := append(test.testDecorator.linkerProps(), test.binaryDecorator.linkerProps()...)
	props = append(props, &test.Properties)
	return props
}

func (test *testBinary) linkerDeps(ctx DepsContext, deps Deps) Deps {
	deps = test.testDecorator.linkerDeps(ctx, deps)
	deps = test.binaryDecorator.linkerDeps(ctx, deps)
	deps.DataLibs = append(deps.DataLibs, test.Properties.Data_libs...)
	deps.DataBins = append(deps.DataBins, test.Properties.Data_bins...)
	return deps
}

func (test *testBinary) linkerFlags(ctx ModuleContext, flags Flags) Flags {
	flags = test.binaryDecorator.linkerFlags(ctx, flags)
	flags = test.testDecorator.linkerFlags(ctx, flags)

	// Add a default rpath to allow tests to dlopen libraries specified in data_libs.
	// Host modules already get an rpath specified in linker.go.
	if !ctx.Host() {
		flags.Global.LdFlags = append(flags.Global.LdFlags, `-Wl,-rpath,\$$ORIGIN`)
	}
	return flags
}

func (test *testBinary) moduleInfoJSON(ctx ModuleContext, moduleInfoJSON *android.ModuleInfoJSON) {
	if ctx.Host() && Bool(test.Properties.Test_options.Unit_test) {
		moduleInfoJSON.CompatibilitySuites = append(moduleInfoJSON.CompatibilitySuites, "host-unit-tests")
	}
	moduleInfoJSON.TestOptionsTags = append(moduleInfoJSON.TestOptionsTags, test.Properties.Test_options.Tags...)
	moduleInfoJSON.TestMainlineModules = append(moduleInfoJSON.TestMainlineModules, test.Properties.Test_mainline_modules...)
	if test.testConfig != nil {
		if _, ok := test.testConfig.(android.WritablePath); ok {
			moduleInfoJSON.AutoTestConfig = []string{"true"}
		}
		moduleInfoJSON.TestConfig = append(moduleInfoJSON.TestConfig, test.testConfig.String())
	}
	moduleInfoJSON.TestConfig = append(moduleInfoJSON.TestConfig, test.extraTestConfigs.Strings()...)

	moduleInfoJSON.DataDependencies = append(moduleInfoJSON.DataDependencies, test.Properties.Data_bins...)

	if len(test.InstallerProperties.Test_suites) > 0 {
		moduleInfoJSON.CompatibilitySuites = append(moduleInfoJSON.CompatibilitySuites, test.InstallerProperties.Test_suites...)
	} else {
		moduleInfoJSON.CompatibilitySuites = append(moduleInfoJSON.CompatibilitySuites, "null-suite")
	}

	test.binaryDecorator.moduleInfoJSON(ctx, moduleInfoJSON)
	test.testDecorator.moduleInfoJSON(ctx, moduleInfoJSON)
	moduleInfoJSON.Class = []string{"NATIVE_TESTS"}

}

func (test *testBinary) testSuiteInfo(ctx ModuleContext) {
	test.testDecorator.testSuiteInfo(ctx)
}

func (test *testBinary) installerProps() []interface{} {
	return append(test.baseInstaller.installerProps(), test.testDecorator.installerProps()...)
}

func (test *testBinary) install(ctx ModuleContext, file android.Path) {
	dataSrcPaths := android.PathsForModuleSrc(ctx, test.Properties.Data)
	dataSrcPaths = append(dataSrcPaths, android.PathsForModuleSrc(ctx, test.Properties.Device_common_data)...)
	dataSrcPaths = append(dataSrcPaths, android.PathsForModuleSrc(ctx, test.Properties.Device_first_data)...)
	dataSrcPaths = append(dataSrcPaths, android.PathsForModuleSrc(ctx, test.Properties.Host_common_data)...)

	for _, dataSrcPath := range dataSrcPaths {
		test.data = append(test.data, android.DataPath{SrcPath: dataSrcPath})
	}

	ctx.VisitDirectDepsProxyWithTag(dataLibDepTag, func(dep android.ModuleProxy) {
		depName := ctx.OtherModuleName(dep)
		linkableDep, ok := android.OtherModuleProvider(ctx, dep, LinkableInfoProvider)
		if !ok {
			ctx.ModuleErrorf("data_lib %q is not a LinkableInterface module", depName)
		}
		if linkableDep.OutputFile.Valid() {
			test.data = append(test.data,
				android.DataPath{SrcPath: linkableDep.OutputFile.Path(),
					RelativeInstallPath: linkableDep.RelativeInstallPath})
		}
	})
	ctx.VisitDirectDepsProxyWithTag(dataBinDepTag, func(dep android.ModuleProxy) {
		depName := ctx.OtherModuleName(dep)
		linkableDep, ok := android.OtherModuleProvider(ctx, dep, LinkableInfoProvider)
		if !ok {
			ctx.ModuleErrorf("data_bin %q is not a LinkableInterface module", depName)
		}
		if linkableDep.OutputFile.Valid() {
			test.data = append(test.data,
				android.DataPath{SrcPath: linkableDep.OutputFile.Path(),
					RelativeInstallPath: linkableDep.RelativeInstallPath})
		}
	})

	testInstallBase := getTestInstallBase(ctx.InVendorOrProduct())
	configs := getTradefedConfigOptions(ctx, &test.Properties, test.isolated(ctx), ctx.Device())

	test.testConfig = tradefed.AutoGenTestConfig(ctx, tradefed.AutoGenTestConfigOptions{
		TestConfigProp:         test.Properties.Test_config,
		TestConfigTemplateProp: test.Properties.Test_config_template,
		TestSuites:             test.testDecorator.InstallerProperties.Test_suites,
		Config:                 configs,
		TestRunnerOptions:      test.Properties.Test_options.Test_runner_options,
		AutoGenConfig:          test.Properties.Auto_gen_config,
		TestInstallBase:        testInstallBase,
		DeviceTemplate:         "${NativeTestConfigTemplate}",
		HostTemplate:           "${NativeHostTestConfigTemplate}",
		StandaloneTest:         test.Properties.Standalone_test,
	})

	test.extraTestConfigs = android.PathsForModuleSrc(ctx, test.Properties.Test_options.Extra_test_configs)

	test.binaryDecorator.baseInstaller.dir = "nativetest"
	test.binaryDecorator.baseInstaller.dir64 = "nativetest64"

	if !Bool(test.Properties.No_named_install_directory) {
		test.binaryDecorator.baseInstaller.relative = ctx.ModuleName()
	} else if String(test.binaryDecorator.baseInstaller.Properties.Relative_install_path) == "" {
		ctx.PropertyErrorf("no_named_install_directory", "Module install directory may only be disabled if relative_install_path is set")
	}

	if ctx.Host() && test.gtest() && test.Properties.Test_options.Unit_test == nil {
		test.Properties.Test_options.Unit_test = proptools.BoolPtr(true)
	}

	if !ctx.Config().KatiEnabled() { // TODO(spandandas): Remove the special case for kati
		// Install the test config in testcases/ directory for atest.
		c, ok := ctx.Module().(*Module)
		if !ok {
			ctx.ModuleErrorf("Not a cc_test module")
		}
		// Install configs in the root of $PRODUCT_OUT/testcases/$module
		testCases := android.PathForModuleInPartitionInstall(ctx, "testcases", ctx.ModuleName()+c.SubName())
		if ctx.PrimaryArch() {
			if test.testConfig != nil {
				ctx.InstallFile(testCases, ctx.ModuleName()+".config", test.testConfig)
			}
			dynamicConfig := android.ExistentPathForSource(ctx, ctx.ModuleDir(), "DynamicConfig.xml")
			if dynamicConfig.Valid() {
				ctx.InstallFile(testCases, ctx.ModuleName()+".dynamic", dynamicConfig.Path())
			}
			for _, extraTestConfig := range test.extraTestConfigs {
				ctx.InstallFile(testCases, extraTestConfig.Base(), extraTestConfig)
			}
		}
		// Install tests and data in arch specific subdir $PRODUCT_OUT/testcases/$module/$arch
		testCases = testCases.Join(ctx, ctx.Target().Arch.ArchType.String())
		ctx.InstallTestData(testCases, test.data)
		ctx.InstallFile(testCases, file.Base(), file)
	}

	test.binaryDecorator.baseInstaller.installTestData(ctx, test.data)
	test.binaryDecorator.baseInstaller.install(ctx, file)
	if Bool(test.Properties.Standalone_test) {
		packagingSpecsBuilder := depset.NewBuilder[android.PackagingSpec](depset.TOPOLOGICAL)

		ctx.VisitDirectDeps(func(dep android.Module) {
			deps := android.OtherModuleProviderOrDefault(ctx, dep, android.InstallFilesProvider)
			packagingSpecsBuilder.Transitive(deps.TransitivePackagingSpecs)
		})

		for _, standaloneTestDep := range packagingSpecsBuilder.Build().ToList() {
			if standaloneTestDep.ToGob().SrcPath == nil {
				continue
			}
			if standaloneTestDep.SkipInstall() {
				continue
			}
			if standaloneTestDep.Partition() == "data" {
				continue
			}
			test.binaryDecorator.baseInstaller.installStandaloneTestDep(ctx, standaloneTestDep)
		}
	}
}

func getTestInstallBase(useVendor bool) string {
	// TODO: (b/167308193) Switch to /data/local/tests/unrestricted as the default install base.
	testInstallBase := "/data/local/tmp"
	if useVendor {
		testInstallBase = "/data/local/tests/vendor"
	}
	return testInstallBase
}

func getTradefedConfigOptions(ctx android.EarlyModuleContext, properties *TestBinaryProperties, isolated bool, device bool) []tradefed.Config {
	var configs []tradefed.Config

	for _, module := range properties.Test_mainline_modules {
		configs = append(configs, tradefed.Option{Name: "config-descriptor:metadata", Key: "mainline-param", Value: module})
	}
	if device {
		if Bool(properties.Require_root) {
			configs = append(configs, tradefed.Object{"target_preparer", "com.android.tradefed.targetprep.RootTargetPreparer", nil})
		} else {
			var options []tradefed.Option
			options = append(options, tradefed.Option{Name: "force-root", Value: "false"})
			configs = append(configs, tradefed.Object{"target_preparer", "com.android.tradefed.targetprep.RootTargetPreparer", options})
		}
		if Bool(properties.Disable_framework) {
			var options []tradefed.Option
			configs = append(configs, tradefed.Object{"target_preparer", "com.android.tradefed.targetprep.StopServicesSetup", options})
		}
	}
	if isolated {
		configs = append(configs, tradefed.Option{Name: "not-shardable", Value: "true"})
	}
	if properties.Test_options.Run_test_as != nil {
		configs = append(configs, tradefed.Option{Name: "run-test-as", Value: String(properties.Test_options.Run_test_as)})
	}
	for _, tag := range properties.Test_options.Test_suite_tag {
		configs = append(configs, tradefed.Option{Name: "test-suite-tag", Value: tag})
	}
	if properties.Test_options.Min_shipping_api_level != nil {
		if properties.Test_options.Vsr_min_shipping_api_level != nil {
			ctx.PropertyErrorf("test_options.min_shipping_api_level", "must not be set at the same time as 'vsr_min_shipping_api_level'.")
		}
		var options []tradefed.Option
		options = append(options, tradefed.Option{Name: "min-api-level", Value: strconv.FormatInt(int64(*properties.Test_options.Min_shipping_api_level), 10)})
		configs = append(configs, tradefed.Object{"module_controller", "com.android.tradefed.testtype.suite.module.ShippingApiLevelModuleController", options})
	}
	if properties.Test_options.Vsr_min_shipping_api_level != nil {
		var options []tradefed.Option
		options = append(options, tradefed.Option{Name: "vsr-min-api-level", Value: strconv.FormatInt(int64(*properties.Test_options.Vsr_min_shipping_api_level), 10)})
		configs = append(configs, tradefed.Object{"module_controller", "com.android.tradefed.testtype.suite.module.ShippingApiLevelModuleController", options})
	}
	if properties.Test_options.Min_vndk_version != nil {
		var options []tradefed.Option
		options = append(options, tradefed.Option{Name: "min-api-level", Value: strconv.FormatInt(int64(*properties.Test_options.Min_vndk_version), 10)})
		options = append(options, tradefed.Option{Name: "api-level-prop", Value: "ro.vndk.version"})
		configs = append(configs, tradefed.Object{"module_controller", "com.android.tradefed.testtype.suite.module.MinApiLevelModuleController", options})
	}
	return configs
}

func NewTest(hod android.HostOrDeviceSupported) *Module {
	module, binary := newBinary(hod)
	module.multilib = android.MultilibBoth
	module.testModule = true
	binary.baseInstaller = NewTestInstaller()

	test := &testBinary{
		testDecorator: &testDecorator{
			linker:    binary.baseLinker,
			installer: binary.baseInstaller,
		},
		binaryDecorator: binary,
		baseCompiler:    NewBaseCompiler(),
	}
	module.compiler = test
	module.linker = test
	module.installer = test
	return module
}

type testLibrary struct {
	*testDecorator
	*libraryDecorator
}

func (test *testLibrary) testLibrary() bool {
	return true
}

func (test *testLibrary) linkerProps() []interface{} {
	var props []interface{}
	props = append(props, test.testDecorator.linkerProps()...)
	return append(props, test.libraryDecorator.linkerProps()...)
}

func (test *testLibrary) linkerDeps(ctx DepsContext, deps Deps) Deps {
	deps = test.testDecorator.linkerDeps(ctx, deps)
	deps = test.libraryDecorator.linkerDeps(ctx, deps)
	return deps
}

func (test *testLibrary) linkerFlags(ctx ModuleContext, flags Flags) Flags {
	flags = test.libraryDecorator.linkerFlags(ctx, flags)
	flags = test.testDecorator.linkerFlags(ctx, flags)
	return flags
}

func (test *testLibrary) moduleInfoJSON(ctx ModuleContext, moduleInfoJSON *android.ModuleInfoJSON) {
	if len(test.InstallerProperties.Test_suites) > 0 {
		moduleInfoJSON.CompatibilitySuites = append(moduleInfoJSON.CompatibilitySuites, test.InstallerProperties.Test_suites...)
	}

	test.libraryDecorator.moduleInfoJSON(ctx, moduleInfoJSON)
	test.testDecorator.moduleInfoJSON(ctx, moduleInfoJSON)
}

func (test *testLibrary) testSuiteInfo(ctx ModuleContext) {
	test.testDecorator.testSuiteInfo(ctx)
}

func (test *testLibrary) installerProps() []interface{} {
	return append(test.baseInstaller.installerProps(), test.testDecorator.installerProps()...)
}

func NewTestLibrary(hod android.HostOrDeviceSupported) *Module {
	module, library := NewLibrary(android.HostAndDeviceSupported)
	library.baseInstaller = NewTestInstaller()
	test := &testLibrary{
		testDecorator: &testDecorator{
			linker:    library.baseLinker,
			installer: library.baseInstaller,
		},
		libraryDecorator: library,
	}
	module.linker = test
	module.installer = test
	return module
}

type BenchmarkProperties struct {
	// list of files or filegroup modules that provide data that should be installed alongside
	// the test
	Data []string `android:"path"`

	// list of compatibility suites (for example "cts", "vts") that the module should be
	// installed into.
	Test_suites []string `android:"arch_variant"`

	// the name of the test configuration (for example "AndroidTest.xml") that should be
	// installed with the module.
	Test_config *string `android:"path,arch_variant"`

	// the name of the test configuration template (for example "AndroidTestTemplate.xml") that
	// should be installed with the module.
	Test_config_template *string `android:"path,arch_variant"`

	// Add RootTargetPreparer to auto generated test config. This guarantees the test to run
	// with root permission.
	Require_root *bool

	// Flag to indicate whether or not to create test config automatically. If AndroidTest.xml
	// doesn't exist next to the Android.bp, this attribute doesn't need to be set to true
	// explicitly.
	Auto_gen_config *bool
}

type benchmarkDecorator struct {
	*binaryDecorator
	Properties BenchmarkProperties
	data       []android.DataPath
	testConfig android.Path
}

func (benchmark *benchmarkDecorator) benchmarkBinary() bool {
	return true
}

func (benchmark *benchmarkDecorator) linkerProps() []interface{} {
	props := benchmark.binaryDecorator.linkerProps()
	props = append(props, &benchmark.Properties)
	return props
}

func (benchmark *benchmarkDecorator) linkerDeps(ctx DepsContext, deps Deps) Deps {
	deps = benchmark.binaryDecorator.linkerDeps(ctx, deps)
	deps.StaticLibs = append(deps.StaticLibs, "libgoogle-benchmark")
	return deps
}

func (benchmark *benchmarkDecorator) install(ctx ModuleContext, file android.Path) {
	for _, d := range android.PathsForModuleSrc(ctx, benchmark.Properties.Data) {
		benchmark.data = append(benchmark.data, android.DataPath{SrcPath: d})
	}

	var configs []tradefed.Config
	if Bool(benchmark.Properties.Require_root) {
		configs = append(configs, tradefed.Object{"target_preparer", "com.android.tradefed.targetprep.RootTargetPreparer", nil})
	}
	benchmark.testConfig = tradefed.AutoGenTestConfig(ctx, tradefed.AutoGenTestConfigOptions{
		TestConfigProp:         benchmark.Properties.Test_config,
		TestConfigTemplateProp: benchmark.Properties.Test_config_template,
		TestSuites:             benchmark.Properties.Test_suites,
		Config:                 configs,
		AutoGenConfig:          benchmark.Properties.Auto_gen_config,
		DeviceTemplate:         "${NativeBenchmarkTestConfigTemplate}",
		HostTemplate:           "${NativeBenchmarkTestConfigTemplate}",
	})

	benchmark.binaryDecorator.baseInstaller.dir = filepath.Join("benchmarktest", ctx.ModuleName())
	benchmark.binaryDecorator.baseInstaller.dir64 = filepath.Join("benchmarktest64", ctx.ModuleName())
	benchmark.binaryDecorator.baseInstaller.installTestData(ctx, benchmark.data)
	benchmark.binaryDecorator.baseInstaller.install(ctx, file)
}

func (benchmark *benchmarkDecorator) moduleInfoJSON(ctx ModuleContext, moduleInfoJSON *android.ModuleInfoJSON) {
	benchmark.binaryDecorator.moduleInfoJSON(ctx, moduleInfoJSON)

	moduleInfoJSON.Class = []string{"NATIVE_TESTS"}
	if len(benchmark.Properties.Test_suites) > 0 {
		moduleInfoJSON.CompatibilitySuites = append(moduleInfoJSON.CompatibilitySuites, benchmark.Properties.Test_suites...)
	} else {
		moduleInfoJSON.CompatibilitySuites = append(moduleInfoJSON.CompatibilitySuites, "null-suite")
	}

	if android.PrefixInList(moduleInfoJSON.CompatibilitySuites, "mts-") &&
		!android.InList("mts", moduleInfoJSON.CompatibilitySuites) {
		moduleInfoJSON.CompatibilitySuites = append(moduleInfoJSON.CompatibilitySuites, "mts")
	}

	if benchmark.testConfig != nil {
		if _, ok := benchmark.testConfig.(android.WritablePath); ok {
			moduleInfoJSON.AutoTestConfig = []string{"true"}
		}
		moduleInfoJSON.TestConfig = []string{benchmark.testConfig.String()}
	}
}

func (benchmark *benchmarkDecorator) testSuiteInfo(ctx ModuleContext) {
	android.SetProvider(ctx, android.TestSuiteInfoProvider, android.TestSuiteInfo{
		TestSuites: benchmark.Properties.Test_suites,
	})
}

func NewBenchmark(hod android.HostOrDeviceSupported) *Module {
	module, binary := newBinary(hod)
	module.multilib = android.MultilibBoth
	binary.baseInstaller = NewBaseInstaller("benchmarktest", "benchmarktest64", InstallInData)

	benchmark := &benchmarkDecorator{
		binaryDecorator: binary,
	}
	module.linker = benchmark
	module.installer = benchmark
	return module
}
