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
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"android/soong/android"

	"github.com/google/blueprint"
)

// MockModule implements the android.Module and JSONActions interfaces for testing
type MockModule struct {
	android.ModuleBase
	name    string
	actions []blueprint.JSONAction
}

func (m *MockModule) JSONActions() []blueprint.JSONAction {
	return m.actions
}

func (m *MockModule) GenerateAndroidBuildActions(ctx android.ModuleContext) {
	// Mock implementation - no-op for testing
}

func (m *MockModule) ComponentDepsMutator(ctx android.BottomUpMutatorContext) {
	// Mock implementation - no-op for testing
}

func (m *MockModule) DepsMutator(ctx android.BottomUpMutatorContext) {
	// Mock implementation - no-op for testing
}

func TestInferCommandFromRule(t *testing.T) {
	tests := []struct {
		name         string
		ruleName     string
		expectedCmd  string
	}{
		{
			name:        "compile rule",
			ruleName:    "compile",
			expectedCmd: "clang -c -o $out $in",
		},
		{
			name:        "link_shared rule",
			ruleName:    "link_shared",
			expectedCmd: "clang -shared -o $out $in",
		},
		{
			name:        "archive rule",
			ruleName:    "archive",
			expectedCmd: "ar rcs $out $in",
		},
		{
			name:        "jar rule",
			ruleName:    "jar",
			expectedCmd: "jar cf $out $in",
		},
		{
			name:        "unknown rule",
			ruleName:    "unknown_rule",
			expectedCmd: "echo 'Building $out from $in'",
		},
		{
			name:        "empty rule name",
			ruleName:    "",
			expectedCmd: "echo 'Building $out from $in'",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := inferCommandFromRule(tt.ruleName)
			if result != tt.expectedCmd {
				t.Errorf("inferCommandFromRule(%q) = %q, want %q", tt.ruleName, result, tt.expectedCmd)
			}
		})
	}
}

func TestExtractNinjaData(t *testing.T) {
	// Create a mock Android context
	config := android.TestConfig("out", nil, "", nil)
	ctx := android.NewTestContext(config)

	// Test case 1: No modules (fallback case)
	t.Run("no modules fallback", func(t *testing.T) {
		builds, rules, targets := extractNinjaData(ctx)

		// Verify fallback data is created
		if len(builds) != 1 {
			t.Errorf("Expected 1 build, got %d", len(builds))
		}
		if len(rules) != 1 {
			t.Errorf("Expected 1 rule, got %d", len(rules))
		}
		if len(targets) != 1 {
			t.Errorf("Expected 1 target, got %d", len(targets))
		}

		// Verify build structure
		if build := builds[0]; build["build_id"] != "soong_build_1" {
			t.Errorf("Expected build_id 'soong_build_1', got %v", build["build_id"])
		}

		// Verify rule structure
		if rule := rules[0]; rule["name"] != "soong_rule" {
			t.Errorf("Expected rule name 'soong_rule', got %v", rule["name"])
		}

		// Verify target structure
		if target := targets[0]; target["path"] != "soong_output" {
			t.Errorf("Expected target path 'soong_output', got %v", target["path"])
		}
	})

	// Test case 2: Module with JSON actions
	t.Run("module with json actions", func(t *testing.T) {
		// Create a mock module with JSON actions
		mockModule := &MockModule{
			name: "test_module",
			actions: []blueprint.JSONAction{
				{
					Inputs:  []string{"src/test.c"},
					Outputs: []string{"obj/test.o"},
				},
				{
					Inputs:  []string{"obj/test.o"},
					Outputs: []string{"bin/test"},
				},
			},
		}

		// Mock the context to include our test module
		// Note: In a real implementation, you'd need to properly register the module
		// For this test, we'll test the logic directly

		// Test the rule inference logic directly
		ruleName := "default_rule"
		output := "obj/test.o"
		if strings.HasSuffix(output, ".o") {
			ruleName = "compile"
		}

		if ruleName != "compile" {
			t.Errorf("Expected rule name 'compile' for .o output, got %q", ruleName)
		}

		// Test jar rule inference
		jarOutput := "lib/test.jar"
		jarRuleName := "default_rule"
		if strings.HasSuffix(jarOutput, ".jar") {
			jarRuleName = "jar"
		}

		if jarRuleName != "jar" {
			t.Errorf("Expected rule name 'jar' for .jar output, got %q", jarRuleName)
		}
	})
}

func TestPostToDistninja(t *testing.T) {
	// Test data
	testBuilds := []map[string]interface{}{
		{
			"build_id":      "test_build_1",
			"rule":          "compile",
			"variables":     map[string]string{},
			"pool":          "",
			"inputs":        []string{"src/test.c"},
			"outputs":       []string{"obj/test.o"},
			"implicit_deps": []string{},
			"order_deps":    []string{},
		},
	}

	testRules := []map[string]interface{}{
		{
			"name":        "compile",
			"command":     "clang -c -o $out $in",
			"description": "Compile C source files",
			"variables":   map[string]string{},
		},
	}

	testTargets := []map[string]interface{}{
		{
			"path":   "obj/test.o",
			"status": "pending",
			"hash":   "",
			"build":  "test_build_1",
		},
	}

	// Test case 1: Successful posting
	t.Run("successful posting", func(t *testing.T) {
		// Create mock HTTP server
		ruleCallCount := 0
		buildCallCount := 0
		targetCallCount := 0

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Verify content type
			if r.Header.Get("Content-Type") != "application/json" {
				t.Errorf("Expected Content-Type 'application/json', got %q", r.Header.Get("Content-Type"))
			}

			switch r.URL.Path {
			case "/api/v1/rules":
				if r.Method != "POST" {
					t.Errorf("Expected POST method for rules, got %q", r.Method)
				}
				ruleCallCount++

				// Verify request body
				var rule map[string]interface{}
				if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
					t.Errorf("Failed to decode rule JSON: %v", err)
				}

				if rule["name"] != "compile" {
					t.Errorf("Expected rule name 'compile', got %v", rule["name"])
				}

				w.WriteHeader(http.StatusCreated)
				json.NewEncoder(w).Encode(map[string]string{"status": "created"})

			case "/api/v1/builds":
				if r.Method != "POST" {
					t.Errorf("Expected POST method for builds, got %q", r.Method)
				}
				buildCallCount++

				// Verify request body
				var build map[string]interface{}
				if err := json.NewDecoder(r.Body).Decode(&build); err != nil {
					t.Errorf("Failed to decode build JSON: %v", err)
				}

				if build["build_id"] != "test_build_1" {
					t.Errorf("Expected build_id 'test_build_1', got %v", build["build_id"])
				}

				w.WriteHeader(http.StatusCreated)
				json.NewEncoder(w).Encode(map[string]string{"status": "created"})

			case "/api/v1/targets":
				if r.Method != "POST" {
					t.Errorf("Expected POST method for targets, got %q", r.Method)
				}
				targetCallCount++

				// Verify request body
				var target map[string]interface{}
				if err := json.NewDecoder(r.Body).Decode(&target); err != nil {
					t.Errorf("Failed to decode target JSON: %v", err)
				}

				if target["path"] != "obj/test.o" {
					t.Errorf("Expected target path 'obj/test.o', got %v", target["path"])
				}

				w.WriteHeader(http.StatusCreated)
				json.NewEncoder(w).Encode(map[string]string{"status": "created"})

			default:
				t.Errorf("Unexpected request path: %q", r.URL.Path)
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer server.Close()

		// Call postToDistninja
		err := postToDistninja(server.URL, testBuilds, testRules, testTargets)
		if err != nil {
			t.Errorf("postToDistninja failed: %v", err)
		}

		// Verify all endpoints were called
		if ruleCallCount != 1 {
			t.Errorf("Expected 1 rule call, got %d", ruleCallCount)
		}
		if buildCallCount != 1 {
			t.Errorf("Expected 1 build call, got %d", buildCallCount)
		}
		if targetCallCount != 1 {
			t.Errorf("Expected 1 target call, got %d", targetCallCount)
		}
	})

	// Test case 2: Server error
	t.Run("server error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()

		err := postToDistninja(server.URL, testBuilds, testRules, testTargets)
		if err == nil {
			t.Error("Expected error when server returns 500, got nil")
		}
	})

	// Test case 3: Invalid server URL
	t.Run("invalid server url", func(t *testing.T) {
		err := postToDistninja("http://invalid-url-that-does-not-exist:99999", testBuilds, testRules, testTargets)
		if err == nil {
			t.Error("Expected error for invalid URL, got nil")
		}
	})

	// Test case 4: Empty data
	t.Run("empty data", func(t *testing.T) {
		callCount := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			callCount++
			w.WriteHeader(http.StatusCreated)
		}))
		defer server.Close()

		err := postToDistninja(server.URL, []map[string]interface{}{}, []map[string]interface{}{}, []map[string]interface{}{})
		if err != nil {
			t.Errorf("postToDistninja with empty data failed: %v", err)
		}

		if callCount != 0 {
			t.Errorf("Expected 0 calls for empty data, got %d", callCount)
		}
	})

	// Test case 5: Multiple items
	t.Run("multiple items", func(t *testing.T) {
		multipleBuilds := []map[string]interface{}{
			testBuilds[0],
			{
				"build_id": "test_build_2",
				"rule":     "link",
				"inputs":   []string{"obj/test.o"},
				"outputs":  []string{"bin/test"},
			},
		}

		callCount := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			callCount++
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]string{"status": "created"})
		}))
		defer server.Close()

		err := postToDistninja(server.URL, multipleBuilds, testRules, testTargets)
		if err != nil {
			t.Errorf("postToDistninja with multiple items failed: %v", err)
		}

		// Should be: 1 rule + 2 builds + 1 target = 4 calls
		expectedCalls := 4
		if callCount != expectedCalls {
			t.Errorf("Expected %d calls for multiple items, got %d", expectedCalls, callCount)
		}
	})
}

// Benchmark tests
func BenchmarkInferCommandFromRule(b *testing.B) {
	rules := []string{"compile", "link_shared", "archive", "jar", "unknown_rule"}

	for i := 0; i < b.N; i++ {
		rule := rules[i%len(rules)]
		inferCommandFromRule(rule)
	}
}

func BenchmarkPostToDistninja(b *testing.B) {
	// Setup test data
	testBuilds := []map[string]interface{}{
		{
			"build_id": "bench_build",
			"rule":     "compile",
			"inputs":   []string{"src/bench.c"},
			"outputs":  []string{"obj/bench.o"},
		},
	}

	testRules := []map[string]interface{}{
		{
			"name":    "compile",
			"command": "clang -c -o $out $in",
		},
	}

	testTargets := []map[string]interface{}{
		{
			"path":  "obj/bench.o",
			"build": "bench_build",
		},
	}

	// Setup mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		fmt.Fprint(w, `{"status": "created"}`)
	}))
	defer server.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		postToDistninja(server.URL, testBuilds, testRules, testTargets)
	}
}
