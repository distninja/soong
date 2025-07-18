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
// source: build_flags_src.proto

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

type ReleaseConfigType int32

const (
	// This is treated as `RELEASE_CONFIG`.
	ReleaseConfigType_CONFIG_TYPE_UNSPECIFIED ReleaseConfigType = 0
	// This is a normal release config.  This is the only ReleaseConfigType with
	// implicit inheritance.
	ReleaseConfigType_RELEASE_CONFIG ReleaseConfigType = 1
	// Same as RELEASE_CONFIG, except no implicit inheritance happens.
	// This is the "root" release config.
	ReleaseConfigType_EXPLICIT_INHERITANCE_CONFIG ReleaseConfigType = 2
	// This is a release config applied based on the TARGET_BUILD_VARIANT
	// environment variable, if the build flag RELEASE_BUILD_USE_VARIANT_FLAGS is
	// enabled.
	ReleaseConfigType_BUILD_VARIANT ReleaseConfigType = 3
)

// Enum value maps for ReleaseConfigType.
var (
	ReleaseConfigType_name = map[int32]string{
		0: "CONFIG_TYPE_UNSPECIFIED",
		1: "RELEASE_CONFIG",
		2: "EXPLICIT_INHERITANCE_CONFIG",
		3: "BUILD_VARIANT",
	}
	ReleaseConfigType_value = map[string]int32{
		"CONFIG_TYPE_UNSPECIFIED":     0,
		"RELEASE_CONFIG":              1,
		"EXPLICIT_INHERITANCE_CONFIG": 2,
		"BUILD_VARIANT":               3,
	}
)

func (x ReleaseConfigType) Enum() *ReleaseConfigType {
	p := new(ReleaseConfigType)
	*p = x
	return p
}

func (x ReleaseConfigType) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (ReleaseConfigType) Descriptor() protoreflect.EnumDescriptor {
	return file_build_flags_src_proto_enumTypes[0].Descriptor()
}

func (ReleaseConfigType) Type() protoreflect.EnumType {
	return &file_build_flags_src_proto_enumTypes[0]
}

func (x ReleaseConfigType) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Do not use.
func (x *ReleaseConfigType) UnmarshalJSON(b []byte) error {
	num, err := protoimpl.X.UnmarshalJSONEnum(x.Descriptor(), b)
	if err != nil {
		return err
	}
	*x = ReleaseConfigType(num)
	return nil
}

// Deprecated: Use ReleaseConfigType.Descriptor instead.
func (ReleaseConfigType) EnumDescriptor() ([]byte, []int) {
	return file_build_flags_src_proto_rawDescGZIP(), []int{0}
}

type Value struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Types that are assignable to Val:
	//
	//	*Value_UnspecifiedValue
	//	*Value_StringValue
	//	*Value_BoolValue
	//	*Value_Obsolete
	Val isValue_Val `protobuf_oneof:"val"`
}

func (x *Value) Reset() {
	*x = Value{}
	if protoimpl.UnsafeEnabled {
		mi := &file_build_flags_src_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Value) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Value) ProtoMessage() {}

func (x *Value) ProtoReflect() protoreflect.Message {
	mi := &file_build_flags_src_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Value.ProtoReflect.Descriptor instead.
func (*Value) Descriptor() ([]byte, []int) {
	return file_build_flags_src_proto_rawDescGZIP(), []int{0}
}

func (m *Value) GetVal() isValue_Val {
	if m != nil {
		return m.Val
	}
	return nil
}

func (x *Value) GetUnspecifiedValue() bool {
	if x, ok := x.GetVal().(*Value_UnspecifiedValue); ok {
		return x.UnspecifiedValue
	}
	return false
}

func (x *Value) GetStringValue() string {
	if x, ok := x.GetVal().(*Value_StringValue); ok {
		return x.StringValue
	}
	return ""
}

func (x *Value) GetBoolValue() bool {
	if x, ok := x.GetVal().(*Value_BoolValue); ok {
		return x.BoolValue
	}
	return false
}

func (x *Value) GetObsolete() bool {
	if x, ok := x.GetVal().(*Value_Obsolete); ok {
		return x.Obsolete
	}
	return false
}

type isValue_Val interface {
	isValue_Val()
}

type Value_UnspecifiedValue struct {
	UnspecifiedValue bool `protobuf:"varint,200,opt,name=unspecified_value,json=unspecifiedValue,oneof"`
}

type Value_StringValue struct {
	StringValue string `protobuf:"bytes,201,opt,name=string_value,json=stringValue,oneof"`
}

type Value_BoolValue struct {
	BoolValue bool `protobuf:"varint,202,opt,name=bool_value,json=boolValue,oneof"`
}

type Value_Obsolete struct {
	// If true, the flag is obsolete.  Assigning it further will be flagged.
	Obsolete bool `protobuf:"varint,203,opt,name=obsolete,oneof"`
}

func (*Value_UnspecifiedValue) isValue_Val() {}

func (*Value_StringValue) isValue_Val() {}

func (*Value_BoolValue) isValue_Val() {}

func (*Value_Obsolete) isValue_Val() {}

// The proto used in the source tree.
type FlagDeclaration struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// The name of the flag.
	// See # name for format detail
	Name *string `protobuf:"bytes,1,opt,name=name" json:"name,omitempty"`
	// Namespace the flag belongs to (required)
	// See # namespace for format detail
	Namespace *string `protobuf:"bytes,2,opt,name=namespace" json:"namespace,omitempty"`
	// Text description of the flag's purpose.
	Description *string `protobuf:"bytes,3,opt,name=description" json:"description,omitempty"`
	// The bug number associated with the flag.
	Bugs []string `protobuf:"bytes,4,rep,name=bugs" json:"bugs,omitempty"`
	// Value for the flag
	Value *Value `protobuf:"bytes,201,opt,name=value" json:"value,omitempty"`
	// Workflow for this flag.
	Workflow *Workflow `protobuf:"varint,205,opt,name=workflow,enum=android.release_config_proto.Workflow" json:"workflow,omitempty"`
	// The container for this flag.  This overrides any default container given
	// in the release_config_map message.
	Containers []string `protobuf:"bytes,206,rep,name=containers" json:"containers,omitempty"`
}

func (x *FlagDeclaration) Reset() {
	*x = FlagDeclaration{}
	if protoimpl.UnsafeEnabled {
		mi := &file_build_flags_src_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *FlagDeclaration) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*FlagDeclaration) ProtoMessage() {}

func (x *FlagDeclaration) ProtoReflect() protoreflect.Message {
	mi := &file_build_flags_src_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use FlagDeclaration.ProtoReflect.Descriptor instead.
func (*FlagDeclaration) Descriptor() ([]byte, []int) {
	return file_build_flags_src_proto_rawDescGZIP(), []int{1}
}

func (x *FlagDeclaration) GetName() string {
	if x != nil && x.Name != nil {
		return *x.Name
	}
	return ""
}

func (x *FlagDeclaration) GetNamespace() string {
	if x != nil && x.Namespace != nil {
		return *x.Namespace
	}
	return ""
}

func (x *FlagDeclaration) GetDescription() string {
	if x != nil && x.Description != nil {
		return *x.Description
	}
	return ""
}

func (x *FlagDeclaration) GetBugs() []string {
	if x != nil {
		return x.Bugs
	}
	return nil
}

func (x *FlagDeclaration) GetValue() *Value {
	if x != nil {
		return x.Value
	}
	return nil
}

func (x *FlagDeclaration) GetWorkflow() Workflow {
	if x != nil && x.Workflow != nil {
		return *x.Workflow
	}
	return Workflow_WORKFLOW_UNSPECIFIED
}

func (x *FlagDeclaration) GetContainers() []string {
	if x != nil {
		return x.Containers
	}
	return nil
}

type FlagValue struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Name of the flag.
	// See # name for format detail
	Name *string `protobuf:"bytes,2,opt,name=name" json:"name,omitempty"`
	// Value for the flag
	Value *Value `protobuf:"bytes,201,opt,name=value" json:"value,omitempty"`
	// If true, the flag is completely removed from the release config as if
	// never declared.
	Redacted *bool `protobuf:"varint,202,opt,name=redacted" json:"redacted,omitempty"`
}

func (x *FlagValue) Reset() {
	*x = FlagValue{}
	if protoimpl.UnsafeEnabled {
		mi := &file_build_flags_src_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *FlagValue) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*FlagValue) ProtoMessage() {}

func (x *FlagValue) ProtoReflect() protoreflect.Message {
	mi := &file_build_flags_src_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use FlagValue.ProtoReflect.Descriptor instead.
func (*FlagValue) Descriptor() ([]byte, []int) {
	return file_build_flags_src_proto_rawDescGZIP(), []int{2}
}

func (x *FlagValue) GetName() string {
	if x != nil && x.Name != nil {
		return *x.Name
	}
	return ""
}

func (x *FlagValue) GetValue() *Value {
	if x != nil {
		return x.Value
	}
	return nil
}

func (x *FlagValue) GetRedacted() bool {
	if x != nil && x.Redacted != nil {
		return *x.Redacted
	}
	return false
}

// This replaces $(call declare-release-config).
type ReleaseConfig struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// The name of the release config.
	// See # name for format detail
	Name *string `protobuf:"bytes,1,opt,name=name" json:"name,omitempty"`
	// From which other release configs does this one inherit?
	Inherits []string `protobuf:"bytes,2,rep,name=inherits" json:"inherits,omitempty"`
	// List of names of the aconfig_value_set soong module(s) for this
	// contribution.
	AconfigValueSets []string `protobuf:"bytes,3,rep,name=aconfig_value_sets,json=aconfigValueSets" json:"aconfig_value_sets,omitempty"`
	// Only aconfig flags are allowed in this release config.
	AconfigFlagsOnly *bool `protobuf:"varint,4,opt,name=aconfig_flags_only,json=aconfigFlagsOnly" json:"aconfig_flags_only,omitempty"`
	// Prior stage(s) for flag advancement (during development).
	// Once a flag has met criteria in a prior stage, it can advance to this one.
	PriorStages []string `protobuf:"bytes,5,rep,name=prior_stages,json=priorStages" json:"prior_stages,omitempty"`
	// The ReleaseConfigType of this release config.
	ReleaseConfigType *ReleaseConfigType `protobuf:"varint,6,opt,name=release_config_type,json=releaseConfigType,enum=android.release_config_proto.ReleaseConfigType" json:"release_config_type,omitempty"`
	// Whether to disallow this release config as TARGET_RELEASE.
	// If true, this release config can only be inherited, it cannot be used
	// directly in a build.
	DisallowLunchUse *bool `protobuf:"varint,7,opt,name=disallow_lunch_use,json=disallowLunchUse" json:"disallow_lunch_use,omitempty"`
}

func (x *ReleaseConfig) Reset() {
	*x = ReleaseConfig{}
	if protoimpl.UnsafeEnabled {
		mi := &file_build_flags_src_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ReleaseConfig) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ReleaseConfig) ProtoMessage() {}

func (x *ReleaseConfig) ProtoReflect() protoreflect.Message {
	mi := &file_build_flags_src_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ReleaseConfig.ProtoReflect.Descriptor instead.
func (*ReleaseConfig) Descriptor() ([]byte, []int) {
	return file_build_flags_src_proto_rawDescGZIP(), []int{3}
}

func (x *ReleaseConfig) GetName() string {
	if x != nil && x.Name != nil {
		return *x.Name
	}
	return ""
}

func (x *ReleaseConfig) GetInherits() []string {
	if x != nil {
		return x.Inherits
	}
	return nil
}

func (x *ReleaseConfig) GetAconfigValueSets() []string {
	if x != nil {
		return x.AconfigValueSets
	}
	return nil
}

func (x *ReleaseConfig) GetAconfigFlagsOnly() bool {
	if x != nil && x.AconfigFlagsOnly != nil {
		return *x.AconfigFlagsOnly
	}
	return false
}

func (x *ReleaseConfig) GetPriorStages() []string {
	if x != nil {
		return x.PriorStages
	}
	return nil
}

func (x *ReleaseConfig) GetReleaseConfigType() ReleaseConfigType {
	if x != nil && x.ReleaseConfigType != nil {
		return *x.ReleaseConfigType
	}
	return ReleaseConfigType_CONFIG_TYPE_UNSPECIFIED
}

func (x *ReleaseConfig) GetDisallowLunchUse() bool {
	if x != nil && x.DisallowLunchUse != nil {
		return *x.DisallowLunchUse
	}
	return false
}

// Any aliases.  These are used for continuous integration builder config.
type ReleaseAlias struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// The name of the alias.
	Name *string `protobuf:"bytes,1,opt,name=name" json:"name,omitempty"`
	// The release that `name` is an alias for.
	Target *string `protobuf:"bytes,2,opt,name=target" json:"target,omitempty"`
}

func (x *ReleaseAlias) Reset() {
	*x = ReleaseAlias{}
	if protoimpl.UnsafeEnabled {
		mi := &file_build_flags_src_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ReleaseAlias) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ReleaseAlias) ProtoMessage() {}

func (x *ReleaseAlias) ProtoReflect() protoreflect.Message {
	mi := &file_build_flags_src_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ReleaseAlias.ProtoReflect.Descriptor instead.
func (*ReleaseAlias) Descriptor() ([]byte, []int) {
	return file_build_flags_src_proto_rawDescGZIP(), []int{4}
}

func (x *ReleaseAlias) GetName() string {
	if x != nil && x.Name != nil {
		return *x.Name
	}
	return ""
}

func (x *ReleaseAlias) GetTarget() string {
	if x != nil && x.Target != nil {
		return *x.Target
	}
	return ""
}

// This provides the data from release_config_map.mk
type ReleaseConfigMap struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Any aliases.
	Aliases []*ReleaseAlias `protobuf:"bytes,1,rep,name=aliases" json:"aliases,omitempty"`
	// Description of this map and its intended use.
	Description *string `protobuf:"bytes,2,opt,name=description" json:"description,omitempty"`
	// The default container for flags declared here.
	DefaultContainers []string `protobuf:"bytes,3,rep,name=default_containers,json=defaultContainers" json:"default_containers,omitempty"`
}

func (x *ReleaseConfigMap) Reset() {
	*x = ReleaseConfigMap{}
	if protoimpl.UnsafeEnabled {
		mi := &file_build_flags_src_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ReleaseConfigMap) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ReleaseConfigMap) ProtoMessage() {}

func (x *ReleaseConfigMap) ProtoReflect() protoreflect.Message {
	mi := &file_build_flags_src_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ReleaseConfigMap.ProtoReflect.Descriptor instead.
func (*ReleaseConfigMap) Descriptor() ([]byte, []int) {
	return file_build_flags_src_proto_rawDescGZIP(), []int{5}
}

func (x *ReleaseConfigMap) GetAliases() []*ReleaseAlias {
	if x != nil {
		return x.Aliases
	}
	return nil
}

func (x *ReleaseConfigMap) GetDescription() string {
	if x != nil && x.Description != nil {
		return *x.Description
	}
	return ""
}

func (x *ReleaseConfigMap) GetDefaultContainers() []string {
	if x != nil {
		return x.DefaultContainers
	}
	return nil
}

var File_build_flags_src_proto protoreflect.FileDescriptor

var file_build_flags_src_proto_rawDesc = []byte{
	0x0a, 0x15, 0x62, 0x75, 0x69, 0x6c, 0x64, 0x5f, 0x66, 0x6c, 0x61, 0x67, 0x73, 0x5f, 0x73, 0x72,
	0x63, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x1c, 0x61, 0x6e, 0x64, 0x72, 0x6f, 0x69, 0x64,
	0x2e, 0x72, 0x65, 0x6c, 0x65, 0x61, 0x73, 0x65, 0x5f, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x5f,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x18, 0x62, 0x75, 0x69, 0x6c, 0x64, 0x5f, 0x66, 0x6c, 0x61,
	0x67, 0x73, 0x5f, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22,
	0xa5, 0x01, 0x0a, 0x05, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x12, 0x2e, 0x0a, 0x11, 0x75, 0x6e, 0x73,
	0x70, 0x65, 0x63, 0x69, 0x66, 0x69, 0x65, 0x64, 0x5f, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0xc8,
	0x01, 0x20, 0x01, 0x28, 0x08, 0x48, 0x00, 0x52, 0x10, 0x75, 0x6e, 0x73, 0x70, 0x65, 0x63, 0x69,
	0x66, 0x69, 0x65, 0x64, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x12, 0x24, 0x0a, 0x0c, 0x73, 0x74, 0x72,
	0x69, 0x6e, 0x67, 0x5f, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0xc9, 0x01, 0x20, 0x01, 0x28, 0x09,
	0x48, 0x00, 0x52, 0x0b, 0x73, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x12,
	0x20, 0x0a, 0x0a, 0x62, 0x6f, 0x6f, 0x6c, 0x5f, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0xca, 0x01,
	0x20, 0x01, 0x28, 0x08, 0x48, 0x00, 0x52, 0x09, 0x62, 0x6f, 0x6f, 0x6c, 0x56, 0x61, 0x6c, 0x75,
	0x65, 0x12, 0x1d, 0x0a, 0x08, 0x6f, 0x62, 0x73, 0x6f, 0x6c, 0x65, 0x74, 0x65, 0x18, 0xcb, 0x01,
	0x20, 0x01, 0x28, 0x08, 0x48, 0x00, 0x52, 0x08, 0x6f, 0x62, 0x73, 0x6f, 0x6c, 0x65, 0x74, 0x65,
	0x42, 0x05, 0x0a, 0x03, 0x76, 0x61, 0x6c, 0x22, 0xa3, 0x02, 0x0a, 0x0f, 0x46, 0x6c, 0x61, 0x67,
	0x44, 0x65, 0x63, 0x6c, 0x61, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x12, 0x0a, 0x04, 0x6e,
	0x61, 0x6d, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12,
	0x1c, 0x0a, 0x09, 0x6e, 0x61, 0x6d, 0x65, 0x73, 0x70, 0x61, 0x63, 0x65, 0x18, 0x02, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x09, 0x6e, 0x61, 0x6d, 0x65, 0x73, 0x70, 0x61, 0x63, 0x65, 0x12, 0x20, 0x0a,
	0x0b, 0x64, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x18, 0x03, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x0b, 0x64, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x12,
	0x12, 0x0a, 0x04, 0x62, 0x75, 0x67, 0x73, 0x18, 0x04, 0x20, 0x03, 0x28, 0x09, 0x52, 0x04, 0x62,
	0x75, 0x67, 0x73, 0x12, 0x3a, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0xc9, 0x01, 0x20,
	0x01, 0x28, 0x0b, 0x32, 0x23, 0x2e, 0x61, 0x6e, 0x64, 0x72, 0x6f, 0x69, 0x64, 0x2e, 0x72, 0x65,
	0x6c, 0x65, 0x61, 0x73, 0x65, 0x5f, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x5f, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x2e, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x12,
	0x43, 0x0a, 0x08, 0x77, 0x6f, 0x72, 0x6b, 0x66, 0x6c, 0x6f, 0x77, 0x18, 0xcd, 0x01, 0x20, 0x01,
	0x28, 0x0e, 0x32, 0x26, 0x2e, 0x61, 0x6e, 0x64, 0x72, 0x6f, 0x69, 0x64, 0x2e, 0x72, 0x65, 0x6c,
	0x65, 0x61, 0x73, 0x65, 0x5f, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x5f, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x2e, 0x57, 0x6f, 0x72, 0x6b, 0x66, 0x6c, 0x6f, 0x77, 0x52, 0x08, 0x77, 0x6f, 0x72, 0x6b,
	0x66, 0x6c, 0x6f, 0x77, 0x12, 0x1f, 0x0a, 0x0a, 0x63, 0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x65,
	0x72, 0x73, 0x18, 0xce, 0x01, 0x20, 0x03, 0x28, 0x09, 0x52, 0x0a, 0x63, 0x6f, 0x6e, 0x74, 0x61,
	0x69, 0x6e, 0x65, 0x72, 0x73, 0x4a, 0x06, 0x08, 0xcf, 0x01, 0x10, 0xd0, 0x01, 0x22, 0x78, 0x0a,
	0x09, 0x46, 0x6c, 0x61, 0x67, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x12, 0x12, 0x0a, 0x04, 0x6e, 0x61,
	0x6d, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x3a,
	0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0xc9, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x23,
	0x2e, 0x61, 0x6e, 0x64, 0x72, 0x6f, 0x69, 0x64, 0x2e, 0x72, 0x65, 0x6c, 0x65, 0x61, 0x73, 0x65,
	0x5f, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x5f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x56, 0x61,
	0x6c, 0x75, 0x65, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x12, 0x1b, 0x0a, 0x08, 0x72, 0x65,
	0x64, 0x61, 0x63, 0x74, 0x65, 0x64, 0x18, 0xca, 0x01, 0x20, 0x01, 0x28, 0x08, 0x52, 0x08, 0x72,
	0x65, 0x64, 0x61, 0x63, 0x74, 0x65, 0x64, 0x22, 0xcd, 0x02, 0x0a, 0x0d, 0x52, 0x65, 0x6c, 0x65,
	0x61, 0x73, 0x65, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x12, 0x12, 0x0a, 0x04, 0x6e, 0x61, 0x6d,
	0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x1a, 0x0a,
	0x08, 0x69, 0x6e, 0x68, 0x65, 0x72, 0x69, 0x74, 0x73, 0x18, 0x02, 0x20, 0x03, 0x28, 0x09, 0x52,
	0x08, 0x69, 0x6e, 0x68, 0x65, 0x72, 0x69, 0x74, 0x73, 0x12, 0x2c, 0x0a, 0x12, 0x61, 0x63, 0x6f,
	0x6e, 0x66, 0x69, 0x67, 0x5f, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x5f, 0x73, 0x65, 0x74, 0x73, 0x18,
	0x03, 0x20, 0x03, 0x28, 0x09, 0x52, 0x10, 0x61, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x56, 0x61,
	0x6c, 0x75, 0x65, 0x53, 0x65, 0x74, 0x73, 0x12, 0x2c, 0x0a, 0x12, 0x61, 0x63, 0x6f, 0x6e, 0x66,
	0x69, 0x67, 0x5f, 0x66, 0x6c, 0x61, 0x67, 0x73, 0x5f, 0x6f, 0x6e, 0x6c, 0x79, 0x18, 0x04, 0x20,
	0x01, 0x28, 0x08, 0x52, 0x10, 0x61, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x46, 0x6c, 0x61, 0x67,
	0x73, 0x4f, 0x6e, 0x6c, 0x79, 0x12, 0x21, 0x0a, 0x0c, 0x70, 0x72, 0x69, 0x6f, 0x72, 0x5f, 0x73,
	0x74, 0x61, 0x67, 0x65, 0x73, 0x18, 0x05, 0x20, 0x03, 0x28, 0x09, 0x52, 0x0b, 0x70, 0x72, 0x69,
	0x6f, 0x72, 0x53, 0x74, 0x61, 0x67, 0x65, 0x73, 0x12, 0x5f, 0x0a, 0x13, 0x72, 0x65, 0x6c, 0x65,
	0x61, 0x73, 0x65, 0x5f, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x5f, 0x74, 0x79, 0x70, 0x65, 0x18,
	0x06, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x2f, 0x2e, 0x61, 0x6e, 0x64, 0x72, 0x6f, 0x69, 0x64, 0x2e,
	0x72, 0x65, 0x6c, 0x65, 0x61, 0x73, 0x65, 0x5f, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x5f, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x52, 0x65, 0x6c, 0x65, 0x61, 0x73, 0x65, 0x43, 0x6f, 0x6e, 0x66,
	0x69, 0x67, 0x54, 0x79, 0x70, 0x65, 0x52, 0x11, 0x72, 0x65, 0x6c, 0x65, 0x61, 0x73, 0x65, 0x43,
	0x6f, 0x6e, 0x66, 0x69, 0x67, 0x54, 0x79, 0x70, 0x65, 0x12, 0x2c, 0x0a, 0x12, 0x64, 0x69, 0x73,
	0x61, 0x6c, 0x6c, 0x6f, 0x77, 0x5f, 0x6c, 0x75, 0x6e, 0x63, 0x68, 0x5f, 0x75, 0x73, 0x65, 0x18,
	0x07, 0x20, 0x01, 0x28, 0x08, 0x52, 0x10, 0x64, 0x69, 0x73, 0x61, 0x6c, 0x6c, 0x6f, 0x77, 0x4c,
	0x75, 0x6e, 0x63, 0x68, 0x55, 0x73, 0x65, 0x22, 0x3a, 0x0a, 0x0c, 0x52, 0x65, 0x6c, 0x65, 0x61,
	0x73, 0x65, 0x41, 0x6c, 0x69, 0x61, 0x73, 0x12, 0x12, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x16, 0x0a, 0x06, 0x74,
	0x61, 0x72, 0x67, 0x65, 0x74, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x74, 0x61, 0x72,
	0x67, 0x65, 0x74, 0x22, 0xa9, 0x01, 0x0a, 0x10, 0x52, 0x65, 0x6c, 0x65, 0x61, 0x73, 0x65, 0x43,
	0x6f, 0x6e, 0x66, 0x69, 0x67, 0x4d, 0x61, 0x70, 0x12, 0x44, 0x0a, 0x07, 0x61, 0x6c, 0x69, 0x61,
	0x73, 0x65, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x2a, 0x2e, 0x61, 0x6e, 0x64, 0x72,
	0x6f, 0x69, 0x64, 0x2e, 0x72, 0x65, 0x6c, 0x65, 0x61, 0x73, 0x65, 0x5f, 0x63, 0x6f, 0x6e, 0x66,
	0x69, 0x67, 0x5f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x52, 0x65, 0x6c, 0x65, 0x61, 0x73, 0x65,
	0x41, 0x6c, 0x69, 0x61, 0x73, 0x52, 0x07, 0x61, 0x6c, 0x69, 0x61, 0x73, 0x65, 0x73, 0x12, 0x20,
	0x0a, 0x0b, 0x64, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x18, 0x02, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x0b, 0x64, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e,
	0x12, 0x2d, 0x0a, 0x12, 0x64, 0x65, 0x66, 0x61, 0x75, 0x6c, 0x74, 0x5f, 0x63, 0x6f, 0x6e, 0x74,
	0x61, 0x69, 0x6e, 0x65, 0x72, 0x73, 0x18, 0x03, 0x20, 0x03, 0x28, 0x09, 0x52, 0x11, 0x64, 0x65,
	0x66, 0x61, 0x75, 0x6c, 0x74, 0x43, 0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x65, 0x72, 0x73, 0x2a,
	0x78, 0x0a, 0x11, 0x52, 0x65, 0x6c, 0x65, 0x61, 0x73, 0x65, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67,
	0x54, 0x79, 0x70, 0x65, 0x12, 0x1b, 0x0a, 0x17, 0x43, 0x4f, 0x4e, 0x46, 0x49, 0x47, 0x5f, 0x54,
	0x59, 0x50, 0x45, 0x5f, 0x55, 0x4e, 0x53, 0x50, 0x45, 0x43, 0x49, 0x46, 0x49, 0x45, 0x44, 0x10,
	0x00, 0x12, 0x12, 0x0a, 0x0e, 0x52, 0x45, 0x4c, 0x45, 0x41, 0x53, 0x45, 0x5f, 0x43, 0x4f, 0x4e,
	0x46, 0x49, 0x47, 0x10, 0x01, 0x12, 0x1f, 0x0a, 0x1b, 0x45, 0x58, 0x50, 0x4c, 0x49, 0x43, 0x49,
	0x54, 0x5f, 0x49, 0x4e, 0x48, 0x45, 0x52, 0x49, 0x54, 0x41, 0x4e, 0x43, 0x45, 0x5f, 0x43, 0x4f,
	0x4e, 0x46, 0x49, 0x47, 0x10, 0x02, 0x12, 0x11, 0x0a, 0x0d, 0x42, 0x55, 0x49, 0x4c, 0x44, 0x5f,
	0x56, 0x41, 0x52, 0x49, 0x41, 0x4e, 0x54, 0x10, 0x03, 0x42, 0x33, 0x5a, 0x31, 0x61, 0x6e, 0x64,
	0x72, 0x6f, 0x69, 0x64, 0x2f, 0x73, 0x6f, 0x6f, 0x6e, 0x67, 0x2f, 0x72, 0x65, 0x6c, 0x65, 0x61,
	0x73, 0x65, 0x5f, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2f, 0x72, 0x65, 0x6c, 0x65, 0x61, 0x73,
	0x65, 0x5f, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x5f, 0x70, 0x72, 0x6f, 0x74, 0x6f,
}

var (
	file_build_flags_src_proto_rawDescOnce sync.Once
	file_build_flags_src_proto_rawDescData = file_build_flags_src_proto_rawDesc
)

func file_build_flags_src_proto_rawDescGZIP() []byte {
	file_build_flags_src_proto_rawDescOnce.Do(func() {
		file_build_flags_src_proto_rawDescData = protoimpl.X.CompressGZIP(file_build_flags_src_proto_rawDescData)
	})
	return file_build_flags_src_proto_rawDescData
}

var file_build_flags_src_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_build_flags_src_proto_msgTypes = make([]protoimpl.MessageInfo, 6)
var file_build_flags_src_proto_goTypes = []interface{}{
	(ReleaseConfigType)(0),   // 0: android.release_config_proto.ReleaseConfigType
	(*Value)(nil),            // 1: android.release_config_proto.Value
	(*FlagDeclaration)(nil),  // 2: android.release_config_proto.FlagDeclaration
	(*FlagValue)(nil),        // 3: android.release_config_proto.FlagValue
	(*ReleaseConfig)(nil),    // 4: android.release_config_proto.ReleaseConfig
	(*ReleaseAlias)(nil),     // 5: android.release_config_proto.ReleaseAlias
	(*ReleaseConfigMap)(nil), // 6: android.release_config_proto.ReleaseConfigMap
	(Workflow)(0),            // 7: android.release_config_proto.Workflow
}
var file_build_flags_src_proto_depIdxs = []int32{
	1, // 0: android.release_config_proto.FlagDeclaration.value:type_name -> android.release_config_proto.Value
	7, // 1: android.release_config_proto.FlagDeclaration.workflow:type_name -> android.release_config_proto.Workflow
	1, // 2: android.release_config_proto.FlagValue.value:type_name -> android.release_config_proto.Value
	0, // 3: android.release_config_proto.ReleaseConfig.release_config_type:type_name -> android.release_config_proto.ReleaseConfigType
	5, // 4: android.release_config_proto.ReleaseConfigMap.aliases:type_name -> android.release_config_proto.ReleaseAlias
	5, // [5:5] is the sub-list for method output_type
	5, // [5:5] is the sub-list for method input_type
	5, // [5:5] is the sub-list for extension type_name
	5, // [5:5] is the sub-list for extension extendee
	0, // [0:5] is the sub-list for field type_name
}

func init() { file_build_flags_src_proto_init() }
func file_build_flags_src_proto_init() {
	if File_build_flags_src_proto != nil {
		return
	}
	file_build_flags_common_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_build_flags_src_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Value); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_build_flags_src_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*FlagDeclaration); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_build_flags_src_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*FlagValue); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_build_flags_src_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ReleaseConfig); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_build_flags_src_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ReleaseAlias); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_build_flags_src_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ReleaseConfigMap); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	file_build_flags_src_proto_msgTypes[0].OneofWrappers = []interface{}{
		(*Value_UnspecifiedValue)(nil),
		(*Value_StringValue)(nil),
		(*Value_BoolValue)(nil),
		(*Value_Obsolete)(nil),
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_build_flags_src_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   6,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_build_flags_src_proto_goTypes,
		DependencyIndexes: file_build_flags_src_proto_depIdxs,
		EnumInfos:         file_build_flags_src_proto_enumTypes,
		MessageInfos:      file_build_flags_src_proto_msgTypes,
	}.Build()
	File_build_flags_src_proto = out.File
	file_build_flags_src_proto_rawDesc = nil
	file_build_flags_src_proto_goTypes = nil
	file_build_flags_src_proto_depIdxs = nil
}
