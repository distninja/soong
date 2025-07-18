//
// Copyright (C) 2024 The Android Open-Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.30.0
// 	protoc        v3.21.12
// source: build_flags_common.proto

package release_config_proto

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type Workflow int32

const (
	Workflow_WORKFLOW_UNSPECIFIED Workflow = 0
	// Deprecated.  Use WORKFLOW_UNSPECIFIED instead.
	Workflow_Workflow_Unspecified Workflow = 0
	// Boolean value flags that progress from false to true.
	Workflow_LAUNCH Workflow = 1
	// String value flags that get updated with new version strings to control
	// prebuilt inclusion.
	Workflow_PREBUILT Workflow = 2
	// Manually managed outside flags.  These are likely to be found in a
	// different directory than flags with other workflows.
	Workflow_MANUAL Workflow = 3
)

// Enum value maps for Workflow.
var (
	Workflow_name = map[int32]string{
		0: "WORKFLOW_UNSPECIFIED",
		// Duplicate value: 0: "Workflow_Unspecified",
		1: "LAUNCH",
		2: "PREBUILT",
		3: "MANUAL",
	}
	Workflow_value = map[string]int32{
		"WORKFLOW_UNSPECIFIED": 0,
		"Workflow_Unspecified": 0,
		"LAUNCH":               1,
		"PREBUILT":             2,
		"MANUAL":               3,
	}
)

func (x Workflow) Enum() *Workflow {
	p := new(Workflow)
	*p = x
	return p
}

func (x Workflow) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (Workflow) Descriptor() protoreflect.EnumDescriptor {
	return file_build_flags_common_proto_enumTypes[0].Descriptor()
}

func (Workflow) Type() protoreflect.EnumType {
	return &file_build_flags_common_proto_enumTypes[0]
}

func (x Workflow) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Do not use.
func (x *Workflow) UnmarshalJSON(b []byte) error {
	num, err := protoimpl.X.UnmarshalJSONEnum(x.Descriptor(), b)
	if err != nil {
		return err
	}
	*x = Workflow(num)
	return nil
}

// Deprecated: Use Workflow.Descriptor instead.
func (Workflow) EnumDescriptor() ([]byte, []int) {
	return file_build_flags_common_proto_rawDescGZIP(), []int{0}
}

var File_build_flags_common_proto protoreflect.FileDescriptor

var file_build_flags_common_proto_rawDesc = []byte{
	0x0a, 0x18, 0x62, 0x75, 0x69, 0x6c, 0x64, 0x5f, 0x66, 0x6c, 0x61, 0x67, 0x73, 0x5f, 0x63, 0x6f,
	0x6d, 0x6d, 0x6f, 0x6e, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x1c, 0x61, 0x6e, 0x64, 0x72,
	0x6f, 0x69, 0x64, 0x2e, 0x72, 0x65, 0x6c, 0x65, 0x61, 0x73, 0x65, 0x5f, 0x63, 0x6f, 0x6e, 0x66,
	0x69, 0x67, 0x5f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2a, 0x68, 0x0a, 0x08, 0x57, 0x6f, 0x72, 0x6b,
	0x66, 0x6c, 0x6f, 0x77, 0x12, 0x18, 0x0a, 0x14, 0x57, 0x4f, 0x52, 0x4b, 0x46, 0x4c, 0x4f, 0x57,
	0x5f, 0x55, 0x4e, 0x53, 0x50, 0x45, 0x43, 0x49, 0x46, 0x49, 0x45, 0x44, 0x10, 0x00, 0x12, 0x18,
	0x0a, 0x14, 0x57, 0x6f, 0x72, 0x6b, 0x66, 0x6c, 0x6f, 0x77, 0x5f, 0x55, 0x6e, 0x73, 0x70, 0x65,
	0x63, 0x69, 0x66, 0x69, 0x65, 0x64, 0x10, 0x00, 0x12, 0x0a, 0x0a, 0x06, 0x4c, 0x41, 0x55, 0x4e,
	0x43, 0x48, 0x10, 0x01, 0x12, 0x0c, 0x0a, 0x08, 0x50, 0x52, 0x45, 0x42, 0x55, 0x49, 0x4c, 0x54,
	0x10, 0x02, 0x12, 0x0a, 0x0a, 0x06, 0x4d, 0x41, 0x4e, 0x55, 0x41, 0x4c, 0x10, 0x03, 0x1a, 0x02,
	0x10, 0x01, 0x42, 0x33, 0x5a, 0x31, 0x61, 0x6e, 0x64, 0x72, 0x6f, 0x69, 0x64, 0x2f, 0x73, 0x6f,
	0x6f, 0x6e, 0x67, 0x2f, 0x72, 0x65, 0x6c, 0x65, 0x61, 0x73, 0x65, 0x5f, 0x63, 0x6f, 0x6e, 0x66,
	0x69, 0x67, 0x2f, 0x72, 0x65, 0x6c, 0x65, 0x61, 0x73, 0x65, 0x5f, 0x63, 0x6f, 0x6e, 0x66, 0x69,
	0x67, 0x5f, 0x70, 0x72, 0x6f, 0x74, 0x6f,
}

var (
	file_build_flags_common_proto_rawDescOnce sync.Once
	file_build_flags_common_proto_rawDescData = file_build_flags_common_proto_rawDesc
)

func file_build_flags_common_proto_rawDescGZIP() []byte {
	file_build_flags_common_proto_rawDescOnce.Do(func() {
		file_build_flags_common_proto_rawDescData = protoimpl.X.CompressGZIP(file_build_flags_common_proto_rawDescData)
	})
	return file_build_flags_common_proto_rawDescData
}

var file_build_flags_common_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_build_flags_common_proto_goTypes = []interface{}{
	(Workflow)(0), // 0: android.release_config_proto.Workflow
}
var file_build_flags_common_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_build_flags_common_proto_init() }
func file_build_flags_common_proto_init() {
	if File_build_flags_common_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_build_flags_common_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   0,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_build_flags_common_proto_goTypes,
		DependencyIndexes: file_build_flags_common_proto_depIdxs,
		EnumInfos:         file_build_flags_common_proto_enumTypes,
	}.Build()
	File_build_flags_common_proto = out.File
	file_build_flags_common_proto_rawDesc = nil
	file_build_flags_common_proto_goTypes = nil
	file_build_flags_common_proto_depIdxs = nil
}
