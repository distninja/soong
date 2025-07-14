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

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"android/soong/android"
	"android/soong/android/allowlists"
	"android/soong/shared"

	"github.com/google/blueprint"
	"github.com/google/blueprint/bootstrap"
	"github.com/google/blueprint/deptools"
	"github.com/google/blueprint/metrics"
	"github.com/google/blueprint/pathtools"
	"github.com/google/blueprint/proptools"
	androidProtobuf "google.golang.org/protobuf/android"
)

var (
	topDir           string
	availableEnvFile string
	usedEnvFile      string

	delveListen string
	delvePath   string

	cmdlineArgs android.CmdArgs

	// Distninja related flags
	useDistninja       bool
	distninjaServerURL string
)

const configCacheFile = "config.cache"

type ConfigCache struct {
	EnvDepsHash                  uint64
	ProductVariableFileTimestamp int64
	SoongBuildFileTimestamp      int64
}

func init() {
	// Flags that make sense in every mode
	flag.StringVar(&topDir, "top", "", "Top directory of the Android source tree")
	flag.StringVar(&cmdlineArgs.SoongOutDir, "soong_out", "", "Soong output directory (usually $TOP/out/soong)")
	flag.StringVar(&availableEnvFile, "available_env", "", "File containing available environment variables")
	flag.StringVar(&usedEnvFile, "used_env", "", "File containing used environment variables")
	flag.StringVar(&cmdlineArgs.OutDir, "out", "", "the ninja builddir directory")
	flag.StringVar(&cmdlineArgs.ModuleListFile, "l", "", "file that lists filepaths to parse")
	flag.StringVar(&cmdlineArgs.KatiSuffix, "kati_suffix", "", "the suffix for kati and ninja files, so that different configurations don't clobber each other")

	// Debug flags
	flag.StringVar(&delveListen, "delve_listen", "", "Delve port to listen on for debugging")
	flag.StringVar(&delvePath, "delve_path", "", "Path to Delve. Only used if --delve_listen is set")
	flag.StringVar(&cmdlineArgs.Cpuprofile, "cpuprofile", "", "write cpu profile to file")
	flag.StringVar(&cmdlineArgs.TraceFile, "trace", "", "write trace to file")
	flag.StringVar(&cmdlineArgs.Memprofile, "memprofile", "", "write memory profile to file")
	flag.BoolVar(&cmdlineArgs.NoGC, "nogc", false, "turn off GC for debugging")

	// Flags representing various modes soong_build can run in
	flag.StringVar(&cmdlineArgs.ModuleGraphFile, "module_graph_file", "", "JSON module graph file to output")
	flag.StringVar(&cmdlineArgs.ModuleActionsFile, "module_actions_file", "", "JSON file to output inputs/outputs of actions of modules")
	flag.StringVar(&cmdlineArgs.DocFile, "soong_docs", "", "build documentation file to output")
	flag.StringVar(&cmdlineArgs.OutFile, "o", "build.ninja", "the Ninja file to output")
	flag.StringVar(&cmdlineArgs.SoongVariables, "soong_variables", "soong.variables", "the file contains all build variables")
	flag.BoolVar(&cmdlineArgs.EmptyNinjaFile, "empty-ninja-file", false, "write out a 0-byte ninja file")
	flag.BoolVar(&cmdlineArgs.BuildFromSourceStub, "build-from-source-stub", false, "build Java stubs from source files instead of API text files")
	flag.BoolVar(&cmdlineArgs.EnsureAllowlistIntegrity, "ensure-allowlist-integrity", false, "verify that allowlisted modules are mixed-built")
	flag.StringVar(&cmdlineArgs.ModuleDebugFile, "soong_module_debug", "", "soong module debug info file to write")
	// Flags that probably shouldn't be flags of soong_build, but we haven't found
	// the time to remove them yet
	flag.BoolVar(&cmdlineArgs.RunGoTests, "t", false, "build and run go tests during bootstrap")
	flag.BoolVar(&cmdlineArgs.IncrementalBuildActions, "incremental-build-actions", false, "generate build actions incrementally")

	// Distninja integration flags
	flag.BoolVar(&useDistninja, "use-distninja", false, "use distninja server instead of generating build.ninja")
	flag.StringVar(&distninjaServerURL, "distninja-server", "http://localhost:9090", "distninja server URL")

	// Disable deterministic randomization in the protobuf package, so incremental
	// builds with unrelated Soong changes don't trigger large rebuilds (since we
	// write out text protos in command lines, and command line changes trigger
	// rebuilds).
	androidProtobuf.DisableRand()
}

func newNameResolver(config android.Config) *android.NameResolver {
	return android.NewNameResolver(config)
}

func newContext(configuration android.Config) *android.Context {
	ctx := android.NewContext(configuration)
	ctx.SetNameInterface(newNameResolver(configuration))
	ctx.SetAllowMissingDependencies(configuration.AllowMissingDependencies())
	ctx.AddSourceRootDirs(configuration.SourceRootDirs()...)
	return ctx
}

func needToWriteNinjaHint(ctx *android.Context) bool {
	switch ctx.Config().GetenvWithDefault("SOONG_GENERATES_NINJA_HINT", "") {
	case "always":
		return true
	case "depend":
		if _, err := os.Stat(filepath.Join(topDir, ctx.Config().OutDir(), ".ninja_log")); errors.Is(err, os.ErrNotExist) {
			return true
		}
	}
	return false
}

func writeNinjaHint(ctx *android.Context) error {
	ctx.BeginEvent("ninja_hint")
	defer ctx.EndEvent("ninja_hint")
	// The current predictor focuses on reducing false negatives.
	// If there are too many false positives (e.g., most modules are marked as positive),
	// real long-running jobs cannot run early.
	// Therefore, the model should be adjusted in this case.
	// The model should also be adjusted if there are critical false negatives.
	predicate := func(j *blueprint.JsonModule) (prioritized bool, weight int) {
		prioritized = false
		weight = 0
		for prefix, w := range allowlists.HugeModuleTypePrefixMap {
			if strings.HasPrefix(j.Type, prefix) {
				prioritized = true
				weight = w
				return
			}
		}
		dep_count := len(j.Deps)
		src_count := 0
		for _, a := range j.Module["Actions"].([]blueprint.JSONAction) {
			src_count += len(a.Inputs)
		}
		input_size := dep_count + src_count

		// Current threshold is an arbitrary value which only consider recall rather than accuracy.
		if input_size > allowlists.INPUT_SIZE_THRESHOLD {
			prioritized = true
			weight += ((input_size) / allowlists.INPUT_SIZE_THRESHOLD) * allowlists.DEFAULT_PRIORITIZED_WEIGHT

			// To prevent some modules from having too large a priority value.
			if weight > allowlists.HIGH_PRIORITIZED_WEIGHT {
				weight = allowlists.HIGH_PRIORITIZED_WEIGHT
			}
		}
		return
	}

	outputsMap := ctx.Context.GetWeightedOutputsFromPredicate(predicate)
	var outputBuilder strings.Builder
	for output, weight := range outputsMap {
		outputBuilder.WriteString(fmt.Sprintf("%s,%d\n", output, weight))
	}
	weightListFile := filepath.Join(topDir, ctx.Config().OutDir(), ".ninja_weight_list")

	err := os.WriteFile(weightListFile, []byte(outputBuilder.String()), 0644)
	if err != nil {
		return fmt.Errorf("could not write ninja weight list file %s", err)
	}
	return nil
}

func writeMetrics(configuration android.Config, eventHandler *metrics.EventHandler, metricsDir string) {
	if len(metricsDir) < 1 {
		fmt.Fprintf(os.Stderr, "\nMissing required env var for generating soong metrics: LOG_DIR\n")
		os.Exit(1)
	}
	metricsFile := filepath.Join(metricsDir, "soong_build_metrics.pb")
	err := android.WriteMetrics(configuration, eventHandler, metricsFile)
	maybeQuit(err, "error writing soong_build metrics %s", metricsFile)
}

func writeJsonModuleGraphAndActions(ctx *android.Context, cmdArgs android.CmdArgs) {
	graphFile, graphErr := os.Create(shared.JoinPath(topDir, cmdArgs.ModuleGraphFile))
	maybeQuit(graphErr, "graph err")
	defer graphFile.Close()
	actionsFile, actionsErr := os.Create(shared.JoinPath(topDir, cmdArgs.ModuleActionsFile))
	maybeQuit(actionsErr, "actions err")
	defer actionsFile.Close()
	ctx.Context.PrintJSONGraphAndActions(graphFile, actionsFile)
}

func writeDepFile(outputFile string, eventHandler *metrics.EventHandler, ninjaDeps []string) {
	eventHandler.Begin("ninja_deps")
	defer eventHandler.End("ninja_deps")
	depFile := shared.JoinPath(topDir, outputFile+".d")
	err := deptools.WriteDepFile(depFile, outputFile, ninjaDeps)
	maybeQuit(err, "error writing depfile '%s'", depFile)
}

// Check if there are changes to the environment file, product variable file and
// soong_build binary, in which case no incremental will be performed. For env
// variables we check the used env file, which will be removed in soong ui if
// there is any changes to the env variables used last time, in which case the
// check below will fail and a full build will be attempted. If any new env
// variables are added in the new run, soong ui won't be able to detect it, the
// used env file check below will pass. But unless there is a soong build code
// change, in which case the soong build binary check will fail, otherwise the
// new env variables shouldn't have any affect.
func incrementalValid(config android.Config, configCacheFile string) (*ConfigCache, bool) {
	var newConfigCache ConfigCache
	data, err := os.ReadFile(shared.JoinPath(topDir, usedEnvFile))
	if err != nil {
		// Clean build
		if os.IsNotExist(err) {
			data = []byte{}
		} else {
			maybeQuit(err, "")
		}
	}

	newConfigCache.EnvDepsHash, err = proptools.CalculateHash(data)
	newConfigCache.ProductVariableFileTimestamp = getFileTimestamp(filepath.Join(topDir, cmdlineArgs.SoongVariables))
	newConfigCache.SoongBuildFileTimestamp = getFileTimestamp(filepath.Join(topDir, config.HostToolDir(), "soong_build"))
	//TODO(b/344917959): out/soong/dexpreopt.config might need to be checked as well.

	file, err := os.Open(configCacheFile)
	if err != nil && os.IsNotExist(err) {
		return &newConfigCache, false
	}
	maybeQuit(err, "")
	defer file.Close()

	var configCache ConfigCache
	decoder := json.NewDecoder(file)
	err = decoder.Decode(&configCache)
	maybeQuit(err, "")

	return &newConfigCache, newConfigCache == configCache
}

func getFileTimestamp(file string) int64 {
	stat, err := os.Stat(file)
	if err == nil {
		return stat.ModTime().UnixMilli()
	} else if !os.IsNotExist(err) {
		maybeQuit(err, "")
	}
	return 0
}

func writeConfigCache(configCache *ConfigCache, configCacheFile string) {
	file, err := os.Create(configCacheFile)
	maybeQuit(err, "")
	defer file.Close()

	encoder := json.NewEncoder(file)
	err = encoder.Encode(*configCache)
	maybeQuit(err, "")
}

// runSoongOnlyBuild runs the standard Soong build in a number of different modes.
// It returns the path to the output file (usually the ninja file) and the deps that need
// to trigger a soong rerun.
func runSoongOnlyBuild(ctx *android.Context) (string, []string) {
	ctx.EventHandler.Begin("soong_build")
	defer ctx.EventHandler.End("soong_build")

	var stopBefore bootstrap.StopBefore
	switch ctx.Config().BuildMode {
	case android.GenerateModuleGraph:
		stopBefore = bootstrap.StopBeforeWriteNinja
	case android.GenerateDocFile:
		stopBefore = bootstrap.StopBeforePrepareBuildActions
	default:
		if useDistninja {
			stopBefore = bootstrap.StopBeforeWriteNinja // Stop before writing ninja file
		} else {
			stopBefore = bootstrap.DoEverything
		}
	}

	ninjaDeps, err := bootstrap.RunBlueprint(cmdlineArgs.Args, stopBefore, ctx.Context, ctx.Config())
	maybeQuit(err, "")

	// Convert the Soong module graph into Bazel BUILD files.
	switch ctx.Config().BuildMode {
	case android.GenerateModuleGraph:
		writeJsonModuleGraphAndActions(ctx, cmdlineArgs)
		return cmdlineArgs.ModuleGraphFile, ninjaDeps
	case android.GenerateDocFile:
		// TODO: we could make writeDocs() return the list of documentation files
		// written and add them to the .d file. Then soong_docs would be re-run
		// whenever one is deleted.
		err := writeDocs(ctx, shared.JoinPath(topDir, cmdlineArgs.DocFile))
		maybeQuit(err, "error building Soong documentation")
		return cmdlineArgs.DocFile, ninjaDeps
	default:
		if useDistninja {
			builds, rules, targets := extractNinjaData(ctx)
			err := postToDistninja(distninjaServerURL, builds, rules, targets)
			maybeQuit(err, "failed to post to distninja")
			return "distninja", ninjaDeps
		}
		if needToWriteNinjaHint(ctx) {
			writeNinjaHint(ctx)
		}
		return cmdlineArgs.OutFile, ninjaDeps
	}
}

// soong_ui dumps the available environment variables to
// soong.environment.available . Then soong_build itself is run with an empty
// environment so that the only way environment variables can be accessed is
// using Config, which tracks access to them.

// At the end of the build, a file called soong.environment.used is written
// containing the current value of all used environment variables. The next
// time soong_ui is run, it checks whether any environment variables that was
// used had changed and if so, it deletes soong.environment.used to cause a
// rebuild.
//
// The dependency of build.ninja on soong.environment.used is declared in
// build.ninja.d
func parseAvailableEnv() map[string]string {
	if availableEnvFile == "" {
		fmt.Fprintf(os.Stderr, "--available_env not set\n")
		os.Exit(1)
	}
	result, err := shared.EnvFromFile(shared.JoinPath(topDir, availableEnvFile))
	maybeQuit(err, "error reading available environment file '%s'", availableEnvFile)
	return result
}

// extractNinjaData extracts build, rule, and target data from the context
func extractNinjaData(ctx *android.Context) (builds []map[string]interface{}, rules []map[string]interface{}, targets []map[string]interface{}) {
	var buildList []map[string]interface{}
	var ruleList []map[string]interface{}
	var targetList []map[string]interface{}

	// Extract rules from the blueprint context
	// Get all defined rules from the context
	blueprintCtx := ctx.Context

	// Extract build actions and rules by iterating through modules
	blueprintCtx.VisitAllModulesIf(
		func(module blueprint.Module) bool { return true },
		func(module blueprint.Module) {
			// Skip if module doesn't implement the expected interface
			if androidModule, ok := module.(android.Module); ok {
				moduleName := ctx.ModuleName(androidModule)

				// Get JSON actions for the module which contain build information
				if jsonActionsProvider, ok := androidModule.(interface{ JSONActions() []blueprint.JSONAction }); ok {
					actions := jsonActionsProvider.JSONActions()

					for i, action := range actions {
						// Create build entry for each action
						buildID := fmt.Sprintf("%s_%d", moduleName, i)

						// Extract rule name from action (may need to infer this)
						ruleName := "default_rule"
						if len(action.Outputs) > 0 {
							// Try to infer rule from output file extension
							for _, output := range action.Outputs {
								if strings.HasSuffix(output, ".o") || strings.HasSuffix(output, ".obj") {
									ruleName = "compile"
								} else if strings.HasSuffix(output, ".so") || strings.HasSuffix(output, ".dll") {
									ruleName = "link_shared"
								} else if strings.HasSuffix(output, ".a") {
									ruleName = "archive"
								} else if strings.HasSuffix(output, ".jar") {
									ruleName = "jar"
								}
								break
							}
						}

						// Create build entry
						build := map[string]interface{}{
							"build_id":      buildID,
							"rule":          ruleName,
							"variables":     map[string]string{},
							"pool":          "",
							"inputs":        action.Inputs,
							"outputs":       action.Outputs,
							"implicit_deps": []string{},
							"order_deps":    []string{},
						}
						buildList = append(buildList, build)

						// Create rule entry if not already exists
						ruleExists := false
						for _, existingRule := range ruleList {
							if existingRule["name"] == ruleName {
								ruleExists = true
								break
							}
						}

						if !ruleExists {
							rule := map[string]interface{}{
								"name":        ruleName,
								"command":     inferCommandFromRule(ruleName),
								"description": fmt.Sprintf("Build rule for %s", ruleName),
								"variables":   map[string]string{},
							}
							ruleList = append(ruleList, rule)
						}

						// Create target entries for outputs
						for _, output := range action.Outputs {
							target := map[string]interface{}{
								"path":   output,
								"status": "pending",
								"hash":   "",
								"build":  buildID,
							}
							targetList = append(targetList, target)
						}
					}
				}
			}
		},
	)

	// If no modules provide JSON actions, try to extract from build params
	if len(buildList) == 0 {
		// Get build parameters from the context if available
		// This is a fallback method to extract some basic information
		ruleList = append(ruleList, map[string]interface{}{
			"name":        "soong_rule",
			"command":     "echo 'Soong build rule'",
			"description": "Default Soong build rule",
			"variables":   map[string]string{},
		})

		buildList = append(buildList, map[string]interface{}{
			"build_id":      "soong_build_1",
			"rule":          "soong_rule",
			"variables":     map[string]string{},
			"pool":          "",
			"inputs":        []string{},
			"outputs":       []string{"soong_output"},
			"implicit_deps": []string{},
			"order_deps":    []string{},
		})

		targetList = append(targetList, map[string]interface{}{
			"path":   "soong_output",
			"status": "pending",
			"hash":   "",
			"build":  "soong_build_1",
		})
	}

	return buildList, ruleList, targetList
}

// inferCommandFromRule provides default commands for common rule types
func inferCommandFromRule(ruleName string) string {
	switch ruleName {
	case "compile":
		return "clang -c -o $out $in"
	case "link_shared":
		return "clang -shared -o $out $in"
	case "archive":
		return "ar rcs $out $in"
	case "jar":
		return "jar cf $out $in"
	default:
		return "echo 'Building $out from $in'"
	}
}

// postToDistninja posts build, rule, and target data to the distninja server
func postToDistninja(serverURL string, builds []map[string]interface{}, rules []map[string]interface{}, targets []map[string]interface{}) error {
	client := &http.Client{Timeout: 30 * time.Second}

	for _, rule := range rules {
		data, _ := json.Marshal(rule)
		resp, err := client.Post(serverURL+"/api/v1/rules", "application/json", bytes.NewReader(data))
		if err != nil {
			return err
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}

	for _, build := range builds {
		data, _ := json.Marshal(build)
		resp, err := client.Post(serverURL+"/api/v1/builds", "application/json", bytes.NewReader(data))
		if err != nil {
			return err
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}

	for _, target := range targets {
		data, _ := json.Marshal(target)
		resp, err := client.Post(serverURL+"/api/v1/targets", "application/json", bytes.NewReader(data))
		if err != nil {
			return err
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}

	return nil
}

func main() {
	flag.Parse()

	soongStartTime := time.Now()

	shared.ReexecWithDelveMaybe(delveListen, delvePath)
	android.InitSandbox(topDir)

	availableEnv := parseAvailableEnv()
	configuration, err := android.NewConfig(cmdlineArgs, availableEnv)
	maybeQuit(err, "")
	if configuration.Getenv("ALLOW_MISSING_DEPENDENCIES") == "true" {
		configuration.SetAllowMissingDependencies()
	}

	// Bypass configuration.Getenv, as LOG_DIR does not need to be dependency tracked. By definition, it will
	// change between every CI build, so tracking it would require re-running Soong for every build.
	metricsDir := availableEnv["LOG_DIR"]

	ctx := newContext(configuration)
	android.StartBackgroundMetrics(configuration)

	var configCache *ConfigCache
	configFile := filepath.Join(topDir, ctx.Config().OutDir(), configCacheFile)
	incremental := false
	ctx.SetIncrementalEnabled(cmdlineArgs.IncrementalBuildActions)
	if cmdlineArgs.IncrementalBuildActions {
		configCache, incremental = incrementalValid(ctx.Config(), configFile)
	}
	ctx.SetIncrementalAnalysis(incremental)

	ctx.Register()
	finalOutputFile, ninjaDeps := runSoongOnlyBuild(ctx)

	ninjaDeps = append(ninjaDeps, configuration.ProductVariablesFileName)
	ninjaDeps = append(ninjaDeps, usedEnvFile)
	if shared.IsDebugging() {
		// Add a non-existent file to the dependencies so that soong_build will rerun when the debugger is
		// enabled even if it completed successfully.
		ninjaDeps = append(ninjaDeps, filepath.Join(configuration.SoongOutDir(), "always_rerun_for_delve"))
	}

	writeDepFile(finalOutputFile, ctx.EventHandler, ninjaDeps)

	if ctx.GetIncrementalEnabled() {
		data, err := shared.EnvFileContents(configuration.EnvDeps())
		maybeQuit(err, "")
		configCache.EnvDepsHash, err = proptools.CalculateHash(data)
		maybeQuit(err, "")
		writeConfigCache(configCache, configFile)
	}

	writeMetrics(configuration, ctx.EventHandler, metricsDir)

	writeUsedEnvironmentFile(configuration)

	err = writeGlobFile(ctx.EventHandler, finalOutputFile, ctx.Globs(), soongStartTime)
	maybeQuit(err, "")

	// Touch the output file so that it's the newest file created by soong_build.
	// This is necessary because, if soong_build generated any files which
	// are ninja inputs to the main output file, then ninja would superfluously
	// rebuild this output file on the next build invocation.
	touch(shared.JoinPath(topDir, finalOutputFile))
}

func writeUsedEnvironmentFile(configuration android.Config) {
	if usedEnvFile == "" {
		return
	}

	path := shared.JoinPath(topDir, usedEnvFile)
	data, err := shared.EnvFileContents(configuration.EnvDeps())
	maybeQuit(err, "error writing used environment file '%s'\n", usedEnvFile)

	err = pathtools.WriteFileIfChanged(path, data, 0666)
	maybeQuit(err, "error writing used environment file '%s'", usedEnvFile)
}

func writeGlobFile(eventHandler *metrics.EventHandler, finalOutFile string, globs pathtools.MultipleGlobResults, soongStartTime time.Time) error {
	eventHandler.Begin("writeGlobFile")
	defer eventHandler.End("writeGlobFile")

	globsFile, err := os.Create(shared.JoinPath(topDir, finalOutFile+".globs"))
	if err != nil {
		return err
	}
	defer globsFile.Close()
	globsFileEncoder := json.NewEncoder(globsFile)
	for _, glob := range globs {
		if err := globsFileEncoder.Encode(glob); err != nil {
			return err
		}
	}

	return os.WriteFile(
		shared.JoinPath(topDir, finalOutFile+".globs_time"),
		[]byte(fmt.Sprintf("%d\n", soongStartTime.UnixMicro())),
		0666,
	)
}

func touch(path string) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	maybeQuit(err, "Error touching '%s'", path)
	err = f.Close()
	maybeQuit(err, "Error touching '%s'", path)

	currentTime := time.Now().Local()
	err = os.Chtimes(path, currentTime, currentTime)
	maybeQuit(err, "error touching '%s'", path)
}

func maybeQuit(err error, format string, args ...interface{}) {
	if err == nil {
		return
	}
	if format != "" {
		fmt.Fprintln(os.Stderr, fmt.Sprintf(format, args...)+": "+err.Error())
	} else {
		fmt.Fprintln(os.Stderr, err)
	}
	os.Exit(1)
}
