// Copyright 2024 Google Inc. All rights reserved.
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

import "encoding/gob"

func init() {
	gob.Register(applicableLicensesPropertyImpl{})
	gob.Register(extraFilesZip{})
	gob.Register(InstallPath{})
	gob.Register(ModuleGenPath{})
	gob.Register(ModuleObjPath{})
	gob.Register(ModuleOutPath{})
	gob.Register(OutputPath{})
	gob.Register(PhonyPath{})
	gob.Register(SourcePath{})
	gob.Register(unstableInfo{})
}
