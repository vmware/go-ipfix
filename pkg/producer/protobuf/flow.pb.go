// Copyright 2020 VMware, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.26.0
// 	protoc        v3.15.0
// source: pkg/producer/protobuf/flow.proto

package protobuf

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

// FlowType1 and FlowType2 are two different proto schemas with same fields. Used
// two different proto schemas to demonstrate that the producer can be built in a
// flexible manner and can support multiple proto schemas.
type FlowType1 struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Header of IPFIX Message.
	TimeReceived   uint32 `protobuf:"varint,1,opt,name=TimeReceived,proto3" json:"TimeReceived,omitempty"`
	SequenceNumber uint32 `protobuf:"varint,2,opt,name=SequenceNumber,proto3" json:"SequenceNumber,omitempty"`
	ObsDomainID    uint32 `protobuf:"varint,3,opt,name=ObsDomainID,proto3" json:"ObsDomainID,omitempty"`
	ExportAddress  string `protobuf:"bytes,33,opt,name=ExportAddress,proto3" json:"ExportAddress,omitempty"`
	// Fields of flow record.
	TimeFlowStartInSecs      uint32 `protobuf:"varint,4,opt,name=TimeFlowStartInSecs,proto3" json:"TimeFlowStartInSecs,omitempty"`
	TimeFlowEndInSecs        uint32 `protobuf:"varint,5,opt,name=TimeFlowEndInSecs,proto3" json:"TimeFlowEndInSecs,omitempty"`
	TimeFlowStartInMilliSecs uint64 `protobuf:"varint,27,opt,name=TimeFlowStartInMilliSecs,proto3" json:"TimeFlowStartInMilliSecs,omitempty"`
	TimeFlowEndInMilliSecs   uint32 `protobuf:"varint,28,opt,name=TimeFlowEndInMilliSecs,proto3" json:"TimeFlowEndInMilliSecs,omitempty"`
	// 5-tuple of flows
	SrcIP   string `protobuf:"bytes,6,opt,name=SrcIP,proto3" json:"SrcIP,omitempty"`
	DstIP   string `protobuf:"bytes,7,opt,name=DstIP,proto3" json:"DstIP,omitempty"`
	SrcPort uint32 `protobuf:"varint,8,opt,name=SrcPort,proto3" json:"SrcPort,omitempty"`
	DstPort uint32 `protobuf:"varint,9,opt,name=DstPort,proto3" json:"DstPort,omitempty"`
	Proto   uint32 `protobuf:"varint,10,opt,name=Proto,proto3" json:"Proto,omitempty"`
	// Statistics of flow in original and reverse directions.
	PacketsTotal        uint64 `protobuf:"varint,11,opt,name=PacketsTotal,proto3" json:"PacketsTotal,omitempty"`
	BytesTotal          uint64 `protobuf:"varint,12,opt,name=BytesTotal,proto3" json:"BytesTotal,omitempty"`
	PacketsDelta        uint64 `protobuf:"varint,13,opt,name=PacketsDelta,proto3" json:"PacketsDelta,omitempty"`
	BytesDelta          uint64 `protobuf:"varint,14,opt,name=BytesDelta,proto3" json:"BytesDelta,omitempty"`
	ReversePacketsTotal uint64 `protobuf:"varint,15,opt,name=ReversePacketsTotal,proto3" json:"ReversePacketsTotal,omitempty"`
	ReverseBytesTotal   uint64 `protobuf:"varint,16,opt,name=ReverseBytesTotal,proto3" json:"ReverseBytesTotal,omitempty"`
	ReversePacketsDelta uint64 `protobuf:"varint,17,opt,name=ReversePacketsDelta,proto3" json:"ReversePacketsDelta,omitempty"`
	ReverseBytesDelta   uint64 `protobuf:"varint,18,opt,name=ReverseBytesDelta,proto3" json:"ReverseBytesDelta,omitempty"`
	// Kubernetes metadata
	SrcPodName             string `protobuf:"bytes,19,opt,name=SrcPodName,proto3" json:"SrcPodName,omitempty"`
	SrcPodNamespace        string `protobuf:"bytes,20,opt,name=SrcPodNamespace,proto3" json:"SrcPodNamespace,omitempty"`
	SrcNodeName            string `protobuf:"bytes,21,opt,name=SrcNodeName,proto3" json:"SrcNodeName,omitempty"`
	DstPodName             string `protobuf:"bytes,22,opt,name=DstPodName,proto3" json:"DstPodName,omitempty"`
	DstPodNamespace        string `protobuf:"bytes,23,opt,name=DstPodNamespace,proto3" json:"DstPodNamespace,omitempty"`
	DstNodeName            string `protobuf:"bytes,24,opt,name=DstNodeName,proto3" json:"DstNodeName,omitempty"`
	DstClusterIP           string `protobuf:"bytes,25,opt,name=DstClusterIP,proto3" json:"DstClusterIP,omitempty"`
	DstServicePort         uint32 `protobuf:"varint,34,opt,name=DstServicePort,proto3" json:"DstServicePort,omitempty"`
	DstServicePortName     string `protobuf:"bytes,26,opt,name=DstServicePortName,proto3" json:"DstServicePortName,omitempty"`
	IngressPolicyName      string `protobuf:"bytes,29,opt,name=IngressPolicyName,proto3" json:"IngressPolicyName,omitempty"`
	IngressPolicyNamespace string `protobuf:"bytes,30,opt,name=IngressPolicyNamespace,proto3" json:"IngressPolicyNamespace,omitempty"`
	EgressPolicyName       string `protobuf:"bytes,31,opt,name=EgressPolicyName,proto3" json:"EgressPolicyName,omitempty"`
	EgressPolicyNamespace  string `protobuf:"bytes,32,opt,name=EgressPolicyNamespace,proto3" json:"EgressPolicyNamespace,omitempty"`
}

func (x *FlowType1) Reset() {
	*x = FlowType1{}
	if protoimpl.UnsafeEnabled {
		mi := &file_pkg_producer_protobuf_flow_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *FlowType1) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*FlowType1) ProtoMessage() {}

func (x *FlowType1) ProtoReflect() protoreflect.Message {
	mi := &file_pkg_producer_protobuf_flow_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use FlowType1.ProtoReflect.Descriptor instead.
func (*FlowType1) Descriptor() ([]byte, []int) {
	return file_pkg_producer_protobuf_flow_proto_rawDescGZIP(), []int{0}
}

func (x *FlowType1) GetTimeReceived() uint32 {
	if x != nil {
		return x.TimeReceived
	}
	return 0
}

func (x *FlowType1) GetSequenceNumber() uint32 {
	if x != nil {
		return x.SequenceNumber
	}
	return 0
}

func (x *FlowType1) GetObsDomainID() uint32 {
	if x != nil {
		return x.ObsDomainID
	}
	return 0
}

func (x *FlowType1) GetExportAddress() string {
	if x != nil {
		return x.ExportAddress
	}
	return ""
}

func (x *FlowType1) GetTimeFlowStartInSecs() uint32 {
	if x != nil {
		return x.TimeFlowStartInSecs
	}
	return 0
}

func (x *FlowType1) GetTimeFlowEndInSecs() uint32 {
	if x != nil {
		return x.TimeFlowEndInSecs
	}
	return 0
}

func (x *FlowType1) GetTimeFlowStartInMilliSecs() uint64 {
	if x != nil {
		return x.TimeFlowStartInMilliSecs
	}
	return 0
}

func (x *FlowType1) GetTimeFlowEndInMilliSecs() uint32 {
	if x != nil {
		return x.TimeFlowEndInMilliSecs
	}
	return 0
}

func (x *FlowType1) GetSrcIP() string {
	if x != nil {
		return x.SrcIP
	}
	return ""
}

func (x *FlowType1) GetDstIP() string {
	if x != nil {
		return x.DstIP
	}
	return ""
}

func (x *FlowType1) GetSrcPort() uint32 {
	if x != nil {
		return x.SrcPort
	}
	return 0
}

func (x *FlowType1) GetDstPort() uint32 {
	if x != nil {
		return x.DstPort
	}
	return 0
}

func (x *FlowType1) GetProto() uint32 {
	if x != nil {
		return x.Proto
	}
	return 0
}

func (x *FlowType1) GetPacketsTotal() uint64 {
	if x != nil {
		return x.PacketsTotal
	}
	return 0
}

func (x *FlowType1) GetBytesTotal() uint64 {
	if x != nil {
		return x.BytesTotal
	}
	return 0
}

func (x *FlowType1) GetPacketsDelta() uint64 {
	if x != nil {
		return x.PacketsDelta
	}
	return 0
}

func (x *FlowType1) GetBytesDelta() uint64 {
	if x != nil {
		return x.BytesDelta
	}
	return 0
}

func (x *FlowType1) GetReversePacketsTotal() uint64 {
	if x != nil {
		return x.ReversePacketsTotal
	}
	return 0
}

func (x *FlowType1) GetReverseBytesTotal() uint64 {
	if x != nil {
		return x.ReverseBytesTotal
	}
	return 0
}

func (x *FlowType1) GetReversePacketsDelta() uint64 {
	if x != nil {
		return x.ReversePacketsDelta
	}
	return 0
}

func (x *FlowType1) GetReverseBytesDelta() uint64 {
	if x != nil {
		return x.ReverseBytesDelta
	}
	return 0
}

func (x *FlowType1) GetSrcPodName() string {
	if x != nil {
		return x.SrcPodName
	}
	return ""
}

func (x *FlowType1) GetSrcPodNamespace() string {
	if x != nil {
		return x.SrcPodNamespace
	}
	return ""
}

func (x *FlowType1) GetSrcNodeName() string {
	if x != nil {
		return x.SrcNodeName
	}
	return ""
}

func (x *FlowType1) GetDstPodName() string {
	if x != nil {
		return x.DstPodName
	}
	return ""
}

func (x *FlowType1) GetDstPodNamespace() string {
	if x != nil {
		return x.DstPodNamespace
	}
	return ""
}

func (x *FlowType1) GetDstNodeName() string {
	if x != nil {
		return x.DstNodeName
	}
	return ""
}

func (x *FlowType1) GetDstClusterIP() string {
	if x != nil {
		return x.DstClusterIP
	}
	return ""
}

func (x *FlowType1) GetDstServicePort() uint32 {
	if x != nil {
		return x.DstServicePort
	}
	return 0
}

func (x *FlowType1) GetDstServicePortName() string {
	if x != nil {
		return x.DstServicePortName
	}
	return ""
}

func (x *FlowType1) GetIngressPolicyName() string {
	if x != nil {
		return x.IngressPolicyName
	}
	return ""
}

func (x *FlowType1) GetIngressPolicyNamespace() string {
	if x != nil {
		return x.IngressPolicyNamespace
	}
	return ""
}

func (x *FlowType1) GetEgressPolicyName() string {
	if x != nil {
		return x.EgressPolicyName
	}
	return ""
}

func (x *FlowType1) GetEgressPolicyNamespace() string {
	if x != nil {
		return x.EgressPolicyNamespace
	}
	return ""
}

type FlowType2 struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Header of IPFIX Message.
	TimeReceived   uint32 `protobuf:"varint,1,opt,name=TimeReceived,proto3" json:"TimeReceived,omitempty"`
	SequenceNumber uint32 `protobuf:"varint,2,opt,name=SequenceNumber,proto3" json:"SequenceNumber,omitempty"`
	ObsDomainID    uint32 `protobuf:"varint,3,opt,name=ObsDomainID,proto3" json:"ObsDomainID,omitempty"`
	ExportAddress  string `protobuf:"bytes,33,opt,name=ExportAddress,proto3" json:"ExportAddress,omitempty"`
	// Fields of flow record.
	TimeFlowStartInSecs      uint32 `protobuf:"varint,4,opt,name=TimeFlowStartInSecs,proto3" json:"TimeFlowStartInSecs,omitempty"`
	TimeFlowEndInSecs        uint32 `protobuf:"varint,5,opt,name=TimeFlowEndInSecs,proto3" json:"TimeFlowEndInSecs,omitempty"`
	TimeFlowStartInMilliSecs uint64 `protobuf:"varint,27,opt,name=TimeFlowStartInMilliSecs,proto3" json:"TimeFlowStartInMilliSecs,omitempty"`
	TimeFlowEndInMilliSecs   uint32 `protobuf:"varint,28,opt,name=TimeFlowEndInMilliSecs,proto3" json:"TimeFlowEndInMilliSecs,omitempty"`
	FlowEndReason            uint32 `protobuf:"varint,35,opt,name=FlowEndReason,proto3" json:"FlowEndReason,omitempty"`
	TcpState                 string `protobuf:"bytes,36,opt,name=TcpState,proto3" json:"TcpState,omitempty"`
	// 5-tuple of flows
	SrcIP   string `protobuf:"bytes,6,opt,name=SrcIP,proto3" json:"SrcIP,omitempty"`
	DstIP   string `protobuf:"bytes,7,opt,name=DstIP,proto3" json:"DstIP,omitempty"`
	SrcPort uint32 `protobuf:"varint,8,opt,name=SrcPort,proto3" json:"SrcPort,omitempty"`
	DstPort uint32 `protobuf:"varint,9,opt,name=DstPort,proto3" json:"DstPort,omitempty"`
	Proto   uint32 `protobuf:"varint,10,opt,name=Proto,proto3" json:"Proto,omitempty"`
	// Statistics of flow in original and reverse directions.
	PacketsTotal        uint64 `protobuf:"varint,11,opt,name=PacketsTotal,proto3" json:"PacketsTotal,omitempty"`
	BytesTotal          uint64 `protobuf:"varint,12,opt,name=BytesTotal,proto3" json:"BytesTotal,omitempty"`
	PacketsDelta        uint64 `protobuf:"varint,13,opt,name=PacketsDelta,proto3" json:"PacketsDelta,omitempty"`
	BytesDelta          uint64 `protobuf:"varint,14,opt,name=BytesDelta,proto3" json:"BytesDelta,omitempty"`
	ReversePacketsTotal uint64 `protobuf:"varint,15,opt,name=ReversePacketsTotal,proto3" json:"ReversePacketsTotal,omitempty"`
	ReverseBytesTotal   uint64 `protobuf:"varint,16,opt,name=ReverseBytesTotal,proto3" json:"ReverseBytesTotal,omitempty"`
	ReversePacketsDelta uint64 `protobuf:"varint,17,opt,name=ReversePacketsDelta,proto3" json:"ReversePacketsDelta,omitempty"`
	ReverseBytesDelta   uint64 `protobuf:"varint,18,opt,name=ReverseBytesDelta,proto3" json:"ReverseBytesDelta,omitempty"`
	// Kubernetes metadata
	SrcPodName             string `protobuf:"bytes,19,opt,name=SrcPodName,proto3" json:"SrcPodName,omitempty"`
	SrcPodNamespace        string `protobuf:"bytes,20,opt,name=SrcPodNamespace,proto3" json:"SrcPodNamespace,omitempty"`
	SrcNodeName            string `protobuf:"bytes,21,opt,name=SrcNodeName,proto3" json:"SrcNodeName,omitempty"`
	DstPodName             string `protobuf:"bytes,22,opt,name=DstPodName,proto3" json:"DstPodName,omitempty"`
	DstPodNamespace        string `protobuf:"bytes,23,opt,name=DstPodNamespace,proto3" json:"DstPodNamespace,omitempty"`
	DstNodeName            string `protobuf:"bytes,24,opt,name=DstNodeName,proto3" json:"DstNodeName,omitempty"`
	DstClusterIP           string `protobuf:"bytes,25,opt,name=DstClusterIP,proto3" json:"DstClusterIP,omitempty"`
	DstServicePort         uint32 `protobuf:"varint,34,opt,name=DstServicePort,proto3" json:"DstServicePort,omitempty"`
	DstServicePortName     string `protobuf:"bytes,26,opt,name=DstServicePortName,proto3" json:"DstServicePortName,omitempty"`
	IngressPolicyName      string `protobuf:"bytes,29,opt,name=IngressPolicyName,proto3" json:"IngressPolicyName,omitempty"`
	IngressPolicyNamespace string `protobuf:"bytes,30,opt,name=IngressPolicyNamespace,proto3" json:"IngressPolicyNamespace,omitempty"`
	EgressPolicyName       string `protobuf:"bytes,31,opt,name=EgressPolicyName,proto3" json:"EgressPolicyName,omitempty"`
	EgressPolicyNamespace  string `protobuf:"bytes,32,opt,name=EgressPolicyNamespace,proto3" json:"EgressPolicyNamespace,omitempty"`
}

func (x *FlowType2) Reset() {
	*x = FlowType2{}
	if protoimpl.UnsafeEnabled {
		mi := &file_pkg_producer_protobuf_flow_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *FlowType2) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*FlowType2) ProtoMessage() {}

func (x *FlowType2) ProtoReflect() protoreflect.Message {
	mi := &file_pkg_producer_protobuf_flow_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use FlowType2.ProtoReflect.Descriptor instead.
func (*FlowType2) Descriptor() ([]byte, []int) {
	return file_pkg_producer_protobuf_flow_proto_rawDescGZIP(), []int{1}
}

func (x *FlowType2) GetTimeReceived() uint32 {
	if x != nil {
		return x.TimeReceived
	}
	return 0
}

func (x *FlowType2) GetSequenceNumber() uint32 {
	if x != nil {
		return x.SequenceNumber
	}
	return 0
}

func (x *FlowType2) GetObsDomainID() uint32 {
	if x != nil {
		return x.ObsDomainID
	}
	return 0
}

func (x *FlowType2) GetExportAddress() string {
	if x != nil {
		return x.ExportAddress
	}
	return ""
}

func (x *FlowType2) GetTimeFlowStartInSecs() uint32 {
	if x != nil {
		return x.TimeFlowStartInSecs
	}
	return 0
}

func (x *FlowType2) GetTimeFlowEndInSecs() uint32 {
	if x != nil {
		return x.TimeFlowEndInSecs
	}
	return 0
}

func (x *FlowType2) GetTimeFlowStartInMilliSecs() uint64 {
	if x != nil {
		return x.TimeFlowStartInMilliSecs
	}
	return 0
}

func (x *FlowType2) GetTimeFlowEndInMilliSecs() uint32 {
	if x != nil {
		return x.TimeFlowEndInMilliSecs
	}
	return 0
}

func (x *FlowType2) GetFlowEndReason() uint32 {
	if x != nil {
		return x.FlowEndReason
	}
	return 0
}

func (x *FlowType2) GetTcpState() string {
	if x != nil {
		return x.TcpState
	}
	return ""
}

func (x *FlowType2) GetSrcIP() string {
	if x != nil {
		return x.SrcIP
	}
	return ""
}

func (x *FlowType2) GetDstIP() string {
	if x != nil {
		return x.DstIP
	}
	return ""
}

func (x *FlowType2) GetSrcPort() uint32 {
	if x != nil {
		return x.SrcPort
	}
	return 0
}

func (x *FlowType2) GetDstPort() uint32 {
	if x != nil {
		return x.DstPort
	}
	return 0
}

func (x *FlowType2) GetProto() uint32 {
	if x != nil {
		return x.Proto
	}
	return 0
}

func (x *FlowType2) GetPacketsTotal() uint64 {
	if x != nil {
		return x.PacketsTotal
	}
	return 0
}

func (x *FlowType2) GetBytesTotal() uint64 {
	if x != nil {
		return x.BytesTotal
	}
	return 0
}

func (x *FlowType2) GetPacketsDelta() uint64 {
	if x != nil {
		return x.PacketsDelta
	}
	return 0
}

func (x *FlowType2) GetBytesDelta() uint64 {
	if x != nil {
		return x.BytesDelta
	}
	return 0
}

func (x *FlowType2) GetReversePacketsTotal() uint64 {
	if x != nil {
		return x.ReversePacketsTotal
	}
	return 0
}

func (x *FlowType2) GetReverseBytesTotal() uint64 {
	if x != nil {
		return x.ReverseBytesTotal
	}
	return 0
}

func (x *FlowType2) GetReversePacketsDelta() uint64 {
	if x != nil {
		return x.ReversePacketsDelta
	}
	return 0
}

func (x *FlowType2) GetReverseBytesDelta() uint64 {
	if x != nil {
		return x.ReverseBytesDelta
	}
	return 0
}

func (x *FlowType2) GetSrcPodName() string {
	if x != nil {
		return x.SrcPodName
	}
	return ""
}

func (x *FlowType2) GetSrcPodNamespace() string {
	if x != nil {
		return x.SrcPodNamespace
	}
	return ""
}

func (x *FlowType2) GetSrcNodeName() string {
	if x != nil {
		return x.SrcNodeName
	}
	return ""
}

func (x *FlowType2) GetDstPodName() string {
	if x != nil {
		return x.DstPodName
	}
	return ""
}

func (x *FlowType2) GetDstPodNamespace() string {
	if x != nil {
		return x.DstPodNamespace
	}
	return ""
}

func (x *FlowType2) GetDstNodeName() string {
	if x != nil {
		return x.DstNodeName
	}
	return ""
}

func (x *FlowType2) GetDstClusterIP() string {
	if x != nil {
		return x.DstClusterIP
	}
	return ""
}

func (x *FlowType2) GetDstServicePort() uint32 {
	if x != nil {
		return x.DstServicePort
	}
	return 0
}

func (x *FlowType2) GetDstServicePortName() string {
	if x != nil {
		return x.DstServicePortName
	}
	return ""
}

func (x *FlowType2) GetIngressPolicyName() string {
	if x != nil {
		return x.IngressPolicyName
	}
	return ""
}

func (x *FlowType2) GetIngressPolicyNamespace() string {
	if x != nil {
		return x.IngressPolicyNamespace
	}
	return ""
}

func (x *FlowType2) GetEgressPolicyName() string {
	if x != nil {
		return x.EgressPolicyName
	}
	return ""
}

func (x *FlowType2) GetEgressPolicyNamespace() string {
	if x != nil {
		return x.EgressPolicyNamespace
	}
	return ""
}

var File_pkg_producer_protobuf_flow_proto protoreflect.FileDescriptor

var file_pkg_producer_protobuf_flow_proto_rawDesc = []byte{
	0x0a, 0x20, 0x70, 0x6b, 0x67, 0x2f, 0x70, 0x72, 0x6f, 0x64, 0x75, 0x63, 0x65, 0x72, 0x2f, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x66, 0x6c, 0x6f, 0x77, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x12, 0x2b, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2e, 0x76,
	0x6d, 0x77, 0x61, 0x72, 0x65, 0x2e, 0x67, 0x6f, 0x69, 0x70, 0x66, 0x69, 0x78, 0x2e, 0x70, 0x72,
	0x6f, 0x64, 0x75, 0x63, 0x65, 0x72, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x22,
	0xcd, 0x0a, 0x0a, 0x09, 0x46, 0x6c, 0x6f, 0x77, 0x54, 0x79, 0x70, 0x65, 0x31, 0x12, 0x22, 0x0a,
	0x0c, 0x54, 0x69, 0x6d, 0x65, 0x52, 0x65, 0x63, 0x65, 0x69, 0x76, 0x65, 0x64, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x0d, 0x52, 0x0c, 0x54, 0x69, 0x6d, 0x65, 0x52, 0x65, 0x63, 0x65, 0x69, 0x76, 0x65,
	0x64, 0x12, 0x26, 0x0a, 0x0e, 0x53, 0x65, 0x71, 0x75, 0x65, 0x6e, 0x63, 0x65, 0x4e, 0x75, 0x6d,
	0x62, 0x65, 0x72, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0e, 0x53, 0x65, 0x71, 0x75, 0x65,
	0x6e, 0x63, 0x65, 0x4e, 0x75, 0x6d, 0x62, 0x65, 0x72, 0x12, 0x20, 0x0a, 0x0b, 0x4f, 0x62, 0x73,
	0x44, 0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x49, 0x44, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0b,
	0x4f, 0x62, 0x73, 0x44, 0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x49, 0x44, 0x12, 0x24, 0x0a, 0x0d, 0x45,
	0x78, 0x70, 0x6f, 0x72, 0x74, 0x41, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x18, 0x21, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x0d, 0x45, 0x78, 0x70, 0x6f, 0x72, 0x74, 0x41, 0x64, 0x64, 0x72, 0x65, 0x73,
	0x73, 0x12, 0x30, 0x0a, 0x13, 0x54, 0x69, 0x6d, 0x65, 0x46, 0x6c, 0x6f, 0x77, 0x53, 0x74, 0x61,
	0x72, 0x74, 0x49, 0x6e, 0x53, 0x65, 0x63, 0x73, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x13,
	0x54, 0x69, 0x6d, 0x65, 0x46, 0x6c, 0x6f, 0x77, 0x53, 0x74, 0x61, 0x72, 0x74, 0x49, 0x6e, 0x53,
	0x65, 0x63, 0x73, 0x12, 0x2c, 0x0a, 0x11, 0x54, 0x69, 0x6d, 0x65, 0x46, 0x6c, 0x6f, 0x77, 0x45,
	0x6e, 0x64, 0x49, 0x6e, 0x53, 0x65, 0x63, 0x73, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x11,
	0x54, 0x69, 0x6d, 0x65, 0x46, 0x6c, 0x6f, 0x77, 0x45, 0x6e, 0x64, 0x49, 0x6e, 0x53, 0x65, 0x63,
	0x73, 0x12, 0x3a, 0x0a, 0x18, 0x54, 0x69, 0x6d, 0x65, 0x46, 0x6c, 0x6f, 0x77, 0x53, 0x74, 0x61,
	0x72, 0x74, 0x49, 0x6e, 0x4d, 0x69, 0x6c, 0x6c, 0x69, 0x53, 0x65, 0x63, 0x73, 0x18, 0x1b, 0x20,
	0x01, 0x28, 0x04, 0x52, 0x18, 0x54, 0x69, 0x6d, 0x65, 0x46, 0x6c, 0x6f, 0x77, 0x53, 0x74, 0x61,
	0x72, 0x74, 0x49, 0x6e, 0x4d, 0x69, 0x6c, 0x6c, 0x69, 0x53, 0x65, 0x63, 0x73, 0x12, 0x36, 0x0a,
	0x16, 0x54, 0x69, 0x6d, 0x65, 0x46, 0x6c, 0x6f, 0x77, 0x45, 0x6e, 0x64, 0x49, 0x6e, 0x4d, 0x69,
	0x6c, 0x6c, 0x69, 0x53, 0x65, 0x63, 0x73, 0x18, 0x1c, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x16, 0x54,
	0x69, 0x6d, 0x65, 0x46, 0x6c, 0x6f, 0x77, 0x45, 0x6e, 0x64, 0x49, 0x6e, 0x4d, 0x69, 0x6c, 0x6c,
	0x69, 0x53, 0x65, 0x63, 0x73, 0x12, 0x14, 0x0a, 0x05, 0x53, 0x72, 0x63, 0x49, 0x50, 0x18, 0x06,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x53, 0x72, 0x63, 0x49, 0x50, 0x12, 0x14, 0x0a, 0x05, 0x44,
	0x73, 0x74, 0x49, 0x50, 0x18, 0x07, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x44, 0x73, 0x74, 0x49,
	0x50, 0x12, 0x18, 0x0a, 0x07, 0x53, 0x72, 0x63, 0x50, 0x6f, 0x72, 0x74, 0x18, 0x08, 0x20, 0x01,
	0x28, 0x0d, 0x52, 0x07, 0x53, 0x72, 0x63, 0x50, 0x6f, 0x72, 0x74, 0x12, 0x18, 0x0a, 0x07, 0x44,
	0x73, 0x74, 0x50, 0x6f, 0x72, 0x74, 0x18, 0x09, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x07, 0x44, 0x73,
	0x74, 0x50, 0x6f, 0x72, 0x74, 0x12, 0x14, 0x0a, 0x05, 0x50, 0x72, 0x6f, 0x74, 0x6f, 0x18, 0x0a,
	0x20, 0x01, 0x28, 0x0d, 0x52, 0x05, 0x50, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x22, 0x0a, 0x0c, 0x50,
	0x61, 0x63, 0x6b, 0x65, 0x74, 0x73, 0x54, 0x6f, 0x74, 0x61, 0x6c, 0x18, 0x0b, 0x20, 0x01, 0x28,
	0x04, 0x52, 0x0c, 0x50, 0x61, 0x63, 0x6b, 0x65, 0x74, 0x73, 0x54, 0x6f, 0x74, 0x61, 0x6c, 0x12,
	0x1e, 0x0a, 0x0a, 0x42, 0x79, 0x74, 0x65, 0x73, 0x54, 0x6f, 0x74, 0x61, 0x6c, 0x18, 0x0c, 0x20,
	0x01, 0x28, 0x04, 0x52, 0x0a, 0x42, 0x79, 0x74, 0x65, 0x73, 0x54, 0x6f, 0x74, 0x61, 0x6c, 0x12,
	0x22, 0x0a, 0x0c, 0x50, 0x61, 0x63, 0x6b, 0x65, 0x74, 0x73, 0x44, 0x65, 0x6c, 0x74, 0x61, 0x18,
	0x0d, 0x20, 0x01, 0x28, 0x04, 0x52, 0x0c, 0x50, 0x61, 0x63, 0x6b, 0x65, 0x74, 0x73, 0x44, 0x65,
	0x6c, 0x74, 0x61, 0x12, 0x1e, 0x0a, 0x0a, 0x42, 0x79, 0x74, 0x65, 0x73, 0x44, 0x65, 0x6c, 0x74,
	0x61, 0x18, 0x0e, 0x20, 0x01, 0x28, 0x04, 0x52, 0x0a, 0x42, 0x79, 0x74, 0x65, 0x73, 0x44, 0x65,
	0x6c, 0x74, 0x61, 0x12, 0x30, 0x0a, 0x13, 0x52, 0x65, 0x76, 0x65, 0x72, 0x73, 0x65, 0x50, 0x61,
	0x63, 0x6b, 0x65, 0x74, 0x73, 0x54, 0x6f, 0x74, 0x61, 0x6c, 0x18, 0x0f, 0x20, 0x01, 0x28, 0x04,
	0x52, 0x13, 0x52, 0x65, 0x76, 0x65, 0x72, 0x73, 0x65, 0x50, 0x61, 0x63, 0x6b, 0x65, 0x74, 0x73,
	0x54, 0x6f, 0x74, 0x61, 0x6c, 0x12, 0x2c, 0x0a, 0x11, 0x52, 0x65, 0x76, 0x65, 0x72, 0x73, 0x65,
	0x42, 0x79, 0x74, 0x65, 0x73, 0x54, 0x6f, 0x74, 0x61, 0x6c, 0x18, 0x10, 0x20, 0x01, 0x28, 0x04,
	0x52, 0x11, 0x52, 0x65, 0x76, 0x65, 0x72, 0x73, 0x65, 0x42, 0x79, 0x74, 0x65, 0x73, 0x54, 0x6f,
	0x74, 0x61, 0x6c, 0x12, 0x30, 0x0a, 0x13, 0x52, 0x65, 0x76, 0x65, 0x72, 0x73, 0x65, 0x50, 0x61,
	0x63, 0x6b, 0x65, 0x74, 0x73, 0x44, 0x65, 0x6c, 0x74, 0x61, 0x18, 0x11, 0x20, 0x01, 0x28, 0x04,
	0x52, 0x13, 0x52, 0x65, 0x76, 0x65, 0x72, 0x73, 0x65, 0x50, 0x61, 0x63, 0x6b, 0x65, 0x74, 0x73,
	0x44, 0x65, 0x6c, 0x74, 0x61, 0x12, 0x2c, 0x0a, 0x11, 0x52, 0x65, 0x76, 0x65, 0x72, 0x73, 0x65,
	0x42, 0x79, 0x74, 0x65, 0x73, 0x44, 0x65, 0x6c, 0x74, 0x61, 0x18, 0x12, 0x20, 0x01, 0x28, 0x04,
	0x52, 0x11, 0x52, 0x65, 0x76, 0x65, 0x72, 0x73, 0x65, 0x42, 0x79, 0x74, 0x65, 0x73, 0x44, 0x65,
	0x6c, 0x74, 0x61, 0x12, 0x1e, 0x0a, 0x0a, 0x53, 0x72, 0x63, 0x50, 0x6f, 0x64, 0x4e, 0x61, 0x6d,
	0x65, 0x18, 0x13, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0a, 0x53, 0x72, 0x63, 0x50, 0x6f, 0x64, 0x4e,
	0x61, 0x6d, 0x65, 0x12, 0x28, 0x0a, 0x0f, 0x53, 0x72, 0x63, 0x50, 0x6f, 0x64, 0x4e, 0x61, 0x6d,
	0x65, 0x73, 0x70, 0x61, 0x63, 0x65, 0x18, 0x14, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0f, 0x53, 0x72,
	0x63, 0x50, 0x6f, 0x64, 0x4e, 0x61, 0x6d, 0x65, 0x73, 0x70, 0x61, 0x63, 0x65, 0x12, 0x20, 0x0a,
	0x0b, 0x53, 0x72, 0x63, 0x4e, 0x6f, 0x64, 0x65, 0x4e, 0x61, 0x6d, 0x65, 0x18, 0x15, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x0b, 0x53, 0x72, 0x63, 0x4e, 0x6f, 0x64, 0x65, 0x4e, 0x61, 0x6d, 0x65, 0x12,
	0x1e, 0x0a, 0x0a, 0x44, 0x73, 0x74, 0x50, 0x6f, 0x64, 0x4e, 0x61, 0x6d, 0x65, 0x18, 0x16, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x0a, 0x44, 0x73, 0x74, 0x50, 0x6f, 0x64, 0x4e, 0x61, 0x6d, 0x65, 0x12,
	0x28, 0x0a, 0x0f, 0x44, 0x73, 0x74, 0x50, 0x6f, 0x64, 0x4e, 0x61, 0x6d, 0x65, 0x73, 0x70, 0x61,
	0x63, 0x65, 0x18, 0x17, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0f, 0x44, 0x73, 0x74, 0x50, 0x6f, 0x64,
	0x4e, 0x61, 0x6d, 0x65, 0x73, 0x70, 0x61, 0x63, 0x65, 0x12, 0x20, 0x0a, 0x0b, 0x44, 0x73, 0x74,
	0x4e, 0x6f, 0x64, 0x65, 0x4e, 0x61, 0x6d, 0x65, 0x18, 0x18, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0b,
	0x44, 0x73, 0x74, 0x4e, 0x6f, 0x64, 0x65, 0x4e, 0x61, 0x6d, 0x65, 0x12, 0x22, 0x0a, 0x0c, 0x44,
	0x73, 0x74, 0x43, 0x6c, 0x75, 0x73, 0x74, 0x65, 0x72, 0x49, 0x50, 0x18, 0x19, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x0c, 0x44, 0x73, 0x74, 0x43, 0x6c, 0x75, 0x73, 0x74, 0x65, 0x72, 0x49, 0x50, 0x12,
	0x26, 0x0a, 0x0e, 0x44, 0x73, 0x74, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x50, 0x6f, 0x72,
	0x74, 0x18, 0x22, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0e, 0x44, 0x73, 0x74, 0x53, 0x65, 0x72, 0x76,
	0x69, 0x63, 0x65, 0x50, 0x6f, 0x72, 0x74, 0x12, 0x2e, 0x0a, 0x12, 0x44, 0x73, 0x74, 0x53, 0x65,
	0x72, 0x76, 0x69, 0x63, 0x65, 0x50, 0x6f, 0x72, 0x74, 0x4e, 0x61, 0x6d, 0x65, 0x18, 0x1a, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x12, 0x44, 0x73, 0x74, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x50,
	0x6f, 0x72, 0x74, 0x4e, 0x61, 0x6d, 0x65, 0x12, 0x2c, 0x0a, 0x11, 0x49, 0x6e, 0x67, 0x72, 0x65,
	0x73, 0x73, 0x50, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x4e, 0x61, 0x6d, 0x65, 0x18, 0x1d, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x11, 0x49, 0x6e, 0x67, 0x72, 0x65, 0x73, 0x73, 0x50, 0x6f, 0x6c, 0x69, 0x63,
	0x79, 0x4e, 0x61, 0x6d, 0x65, 0x12, 0x36, 0x0a, 0x16, 0x49, 0x6e, 0x67, 0x72, 0x65, 0x73, 0x73,
	0x50, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x4e, 0x61, 0x6d, 0x65, 0x73, 0x70, 0x61, 0x63, 0x65, 0x18,
	0x1e, 0x20, 0x01, 0x28, 0x09, 0x52, 0x16, 0x49, 0x6e, 0x67, 0x72, 0x65, 0x73, 0x73, 0x50, 0x6f,
	0x6c, 0x69, 0x63, 0x79, 0x4e, 0x61, 0x6d, 0x65, 0x73, 0x70, 0x61, 0x63, 0x65, 0x12, 0x2a, 0x0a,
	0x10, 0x45, 0x67, 0x72, 0x65, 0x73, 0x73, 0x50, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x4e, 0x61, 0x6d,
	0x65, 0x18, 0x1f, 0x20, 0x01, 0x28, 0x09, 0x52, 0x10, 0x45, 0x67, 0x72, 0x65, 0x73, 0x73, 0x50,
	0x6f, 0x6c, 0x69, 0x63, 0x79, 0x4e, 0x61, 0x6d, 0x65, 0x12, 0x34, 0x0a, 0x15, 0x45, 0x67, 0x72,
	0x65, 0x73, 0x73, 0x50, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x4e, 0x61, 0x6d, 0x65, 0x73, 0x70, 0x61,
	0x63, 0x65, 0x18, 0x20, 0x20, 0x01, 0x28, 0x09, 0x52, 0x15, 0x45, 0x67, 0x72, 0x65, 0x73, 0x73,
	0x50, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x4e, 0x61, 0x6d, 0x65, 0x73, 0x70, 0x61, 0x63, 0x65, 0x22,
	0x8f, 0x0b, 0x0a, 0x09, 0x46, 0x6c, 0x6f, 0x77, 0x54, 0x79, 0x70, 0x65, 0x32, 0x12, 0x22, 0x0a,
	0x0c, 0x54, 0x69, 0x6d, 0x65, 0x52, 0x65, 0x63, 0x65, 0x69, 0x76, 0x65, 0x64, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x0d, 0x52, 0x0c, 0x54, 0x69, 0x6d, 0x65, 0x52, 0x65, 0x63, 0x65, 0x69, 0x76, 0x65,
	0x64, 0x12, 0x26, 0x0a, 0x0e, 0x53, 0x65, 0x71, 0x75, 0x65, 0x6e, 0x63, 0x65, 0x4e, 0x75, 0x6d,
	0x62, 0x65, 0x72, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0e, 0x53, 0x65, 0x71, 0x75, 0x65,
	0x6e, 0x63, 0x65, 0x4e, 0x75, 0x6d, 0x62, 0x65, 0x72, 0x12, 0x20, 0x0a, 0x0b, 0x4f, 0x62, 0x73,
	0x44, 0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x49, 0x44, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0b,
	0x4f, 0x62, 0x73, 0x44, 0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x49, 0x44, 0x12, 0x24, 0x0a, 0x0d, 0x45,
	0x78, 0x70, 0x6f, 0x72, 0x74, 0x41, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x18, 0x21, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x0d, 0x45, 0x78, 0x70, 0x6f, 0x72, 0x74, 0x41, 0x64, 0x64, 0x72, 0x65, 0x73,
	0x73, 0x12, 0x30, 0x0a, 0x13, 0x54, 0x69, 0x6d, 0x65, 0x46, 0x6c, 0x6f, 0x77, 0x53, 0x74, 0x61,
	0x72, 0x74, 0x49, 0x6e, 0x53, 0x65, 0x63, 0x73, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x13,
	0x54, 0x69, 0x6d, 0x65, 0x46, 0x6c, 0x6f, 0x77, 0x53, 0x74, 0x61, 0x72, 0x74, 0x49, 0x6e, 0x53,
	0x65, 0x63, 0x73, 0x12, 0x2c, 0x0a, 0x11, 0x54, 0x69, 0x6d, 0x65, 0x46, 0x6c, 0x6f, 0x77, 0x45,
	0x6e, 0x64, 0x49, 0x6e, 0x53, 0x65, 0x63, 0x73, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x11,
	0x54, 0x69, 0x6d, 0x65, 0x46, 0x6c, 0x6f, 0x77, 0x45, 0x6e, 0x64, 0x49, 0x6e, 0x53, 0x65, 0x63,
	0x73, 0x12, 0x3a, 0x0a, 0x18, 0x54, 0x69, 0x6d, 0x65, 0x46, 0x6c, 0x6f, 0x77, 0x53, 0x74, 0x61,
	0x72, 0x74, 0x49, 0x6e, 0x4d, 0x69, 0x6c, 0x6c, 0x69, 0x53, 0x65, 0x63, 0x73, 0x18, 0x1b, 0x20,
	0x01, 0x28, 0x04, 0x52, 0x18, 0x54, 0x69, 0x6d, 0x65, 0x46, 0x6c, 0x6f, 0x77, 0x53, 0x74, 0x61,
	0x72, 0x74, 0x49, 0x6e, 0x4d, 0x69, 0x6c, 0x6c, 0x69, 0x53, 0x65, 0x63, 0x73, 0x12, 0x36, 0x0a,
	0x16, 0x54, 0x69, 0x6d, 0x65, 0x46, 0x6c, 0x6f, 0x77, 0x45, 0x6e, 0x64, 0x49, 0x6e, 0x4d, 0x69,
	0x6c, 0x6c, 0x69, 0x53, 0x65, 0x63, 0x73, 0x18, 0x1c, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x16, 0x54,
	0x69, 0x6d, 0x65, 0x46, 0x6c, 0x6f, 0x77, 0x45, 0x6e, 0x64, 0x49, 0x6e, 0x4d, 0x69, 0x6c, 0x6c,
	0x69, 0x53, 0x65, 0x63, 0x73, 0x12, 0x24, 0x0a, 0x0d, 0x46, 0x6c, 0x6f, 0x77, 0x45, 0x6e, 0x64,
	0x52, 0x65, 0x61, 0x73, 0x6f, 0x6e, 0x18, 0x23, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0d, 0x46, 0x6c,
	0x6f, 0x77, 0x45, 0x6e, 0x64, 0x52, 0x65, 0x61, 0x73, 0x6f, 0x6e, 0x12, 0x1a, 0x0a, 0x08, 0x54,
	0x63, 0x70, 0x53, 0x74, 0x61, 0x74, 0x65, 0x18, 0x24, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x54,
	0x63, 0x70, 0x53, 0x74, 0x61, 0x74, 0x65, 0x12, 0x14, 0x0a, 0x05, 0x53, 0x72, 0x63, 0x49, 0x50,
	0x18, 0x06, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x53, 0x72, 0x63, 0x49, 0x50, 0x12, 0x14, 0x0a,
	0x05, 0x44, 0x73, 0x74, 0x49, 0x50, 0x18, 0x07, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x44, 0x73,
	0x74, 0x49, 0x50, 0x12, 0x18, 0x0a, 0x07, 0x53, 0x72, 0x63, 0x50, 0x6f, 0x72, 0x74, 0x18, 0x08,
	0x20, 0x01, 0x28, 0x0d, 0x52, 0x07, 0x53, 0x72, 0x63, 0x50, 0x6f, 0x72, 0x74, 0x12, 0x18, 0x0a,
	0x07, 0x44, 0x73, 0x74, 0x50, 0x6f, 0x72, 0x74, 0x18, 0x09, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x07,
	0x44, 0x73, 0x74, 0x50, 0x6f, 0x72, 0x74, 0x12, 0x14, 0x0a, 0x05, 0x50, 0x72, 0x6f, 0x74, 0x6f,
	0x18, 0x0a, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x05, 0x50, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x22, 0x0a,
	0x0c, 0x50, 0x61, 0x63, 0x6b, 0x65, 0x74, 0x73, 0x54, 0x6f, 0x74, 0x61, 0x6c, 0x18, 0x0b, 0x20,
	0x01, 0x28, 0x04, 0x52, 0x0c, 0x50, 0x61, 0x63, 0x6b, 0x65, 0x74, 0x73, 0x54, 0x6f, 0x74, 0x61,
	0x6c, 0x12, 0x1e, 0x0a, 0x0a, 0x42, 0x79, 0x74, 0x65, 0x73, 0x54, 0x6f, 0x74, 0x61, 0x6c, 0x18,
	0x0c, 0x20, 0x01, 0x28, 0x04, 0x52, 0x0a, 0x42, 0x79, 0x74, 0x65, 0x73, 0x54, 0x6f, 0x74, 0x61,
	0x6c, 0x12, 0x22, 0x0a, 0x0c, 0x50, 0x61, 0x63, 0x6b, 0x65, 0x74, 0x73, 0x44, 0x65, 0x6c, 0x74,
	0x61, 0x18, 0x0d, 0x20, 0x01, 0x28, 0x04, 0x52, 0x0c, 0x50, 0x61, 0x63, 0x6b, 0x65, 0x74, 0x73,
	0x44, 0x65, 0x6c, 0x74, 0x61, 0x12, 0x1e, 0x0a, 0x0a, 0x42, 0x79, 0x74, 0x65, 0x73, 0x44, 0x65,
	0x6c, 0x74, 0x61, 0x18, 0x0e, 0x20, 0x01, 0x28, 0x04, 0x52, 0x0a, 0x42, 0x79, 0x74, 0x65, 0x73,
	0x44, 0x65, 0x6c, 0x74, 0x61, 0x12, 0x30, 0x0a, 0x13, 0x52, 0x65, 0x76, 0x65, 0x72, 0x73, 0x65,
	0x50, 0x61, 0x63, 0x6b, 0x65, 0x74, 0x73, 0x54, 0x6f, 0x74, 0x61, 0x6c, 0x18, 0x0f, 0x20, 0x01,
	0x28, 0x04, 0x52, 0x13, 0x52, 0x65, 0x76, 0x65, 0x72, 0x73, 0x65, 0x50, 0x61, 0x63, 0x6b, 0x65,
	0x74, 0x73, 0x54, 0x6f, 0x74, 0x61, 0x6c, 0x12, 0x2c, 0x0a, 0x11, 0x52, 0x65, 0x76, 0x65, 0x72,
	0x73, 0x65, 0x42, 0x79, 0x74, 0x65, 0x73, 0x54, 0x6f, 0x74, 0x61, 0x6c, 0x18, 0x10, 0x20, 0x01,
	0x28, 0x04, 0x52, 0x11, 0x52, 0x65, 0x76, 0x65, 0x72, 0x73, 0x65, 0x42, 0x79, 0x74, 0x65, 0x73,
	0x54, 0x6f, 0x74, 0x61, 0x6c, 0x12, 0x30, 0x0a, 0x13, 0x52, 0x65, 0x76, 0x65, 0x72, 0x73, 0x65,
	0x50, 0x61, 0x63, 0x6b, 0x65, 0x74, 0x73, 0x44, 0x65, 0x6c, 0x74, 0x61, 0x18, 0x11, 0x20, 0x01,
	0x28, 0x04, 0x52, 0x13, 0x52, 0x65, 0x76, 0x65, 0x72, 0x73, 0x65, 0x50, 0x61, 0x63, 0x6b, 0x65,
	0x74, 0x73, 0x44, 0x65, 0x6c, 0x74, 0x61, 0x12, 0x2c, 0x0a, 0x11, 0x52, 0x65, 0x76, 0x65, 0x72,
	0x73, 0x65, 0x42, 0x79, 0x74, 0x65, 0x73, 0x44, 0x65, 0x6c, 0x74, 0x61, 0x18, 0x12, 0x20, 0x01,
	0x28, 0x04, 0x52, 0x11, 0x52, 0x65, 0x76, 0x65, 0x72, 0x73, 0x65, 0x42, 0x79, 0x74, 0x65, 0x73,
	0x44, 0x65, 0x6c, 0x74, 0x61, 0x12, 0x1e, 0x0a, 0x0a, 0x53, 0x72, 0x63, 0x50, 0x6f, 0x64, 0x4e,
	0x61, 0x6d, 0x65, 0x18, 0x13, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0a, 0x53, 0x72, 0x63, 0x50, 0x6f,
	0x64, 0x4e, 0x61, 0x6d, 0x65, 0x12, 0x28, 0x0a, 0x0f, 0x53, 0x72, 0x63, 0x50, 0x6f, 0x64, 0x4e,
	0x61, 0x6d, 0x65, 0x73, 0x70, 0x61, 0x63, 0x65, 0x18, 0x14, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0f,
	0x53, 0x72, 0x63, 0x50, 0x6f, 0x64, 0x4e, 0x61, 0x6d, 0x65, 0x73, 0x70, 0x61, 0x63, 0x65, 0x12,
	0x20, 0x0a, 0x0b, 0x53, 0x72, 0x63, 0x4e, 0x6f, 0x64, 0x65, 0x4e, 0x61, 0x6d, 0x65, 0x18, 0x15,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x0b, 0x53, 0x72, 0x63, 0x4e, 0x6f, 0x64, 0x65, 0x4e, 0x61, 0x6d,
	0x65, 0x12, 0x1e, 0x0a, 0x0a, 0x44, 0x73, 0x74, 0x50, 0x6f, 0x64, 0x4e, 0x61, 0x6d, 0x65, 0x18,
	0x16, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0a, 0x44, 0x73, 0x74, 0x50, 0x6f, 0x64, 0x4e, 0x61, 0x6d,
	0x65, 0x12, 0x28, 0x0a, 0x0f, 0x44, 0x73, 0x74, 0x50, 0x6f, 0x64, 0x4e, 0x61, 0x6d, 0x65, 0x73,
	0x70, 0x61, 0x63, 0x65, 0x18, 0x17, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0f, 0x44, 0x73, 0x74, 0x50,
	0x6f, 0x64, 0x4e, 0x61, 0x6d, 0x65, 0x73, 0x70, 0x61, 0x63, 0x65, 0x12, 0x20, 0x0a, 0x0b, 0x44,
	0x73, 0x74, 0x4e, 0x6f, 0x64, 0x65, 0x4e, 0x61, 0x6d, 0x65, 0x18, 0x18, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x0b, 0x44, 0x73, 0x74, 0x4e, 0x6f, 0x64, 0x65, 0x4e, 0x61, 0x6d, 0x65, 0x12, 0x22, 0x0a,
	0x0c, 0x44, 0x73, 0x74, 0x43, 0x6c, 0x75, 0x73, 0x74, 0x65, 0x72, 0x49, 0x50, 0x18, 0x19, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x0c, 0x44, 0x73, 0x74, 0x43, 0x6c, 0x75, 0x73, 0x74, 0x65, 0x72, 0x49,
	0x50, 0x12, 0x26, 0x0a, 0x0e, 0x44, 0x73, 0x74, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x50,
	0x6f, 0x72, 0x74, 0x18, 0x22, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0e, 0x44, 0x73, 0x74, 0x53, 0x65,
	0x72, 0x76, 0x69, 0x63, 0x65, 0x50, 0x6f, 0x72, 0x74, 0x12, 0x2e, 0x0a, 0x12, 0x44, 0x73, 0x74,
	0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x50, 0x6f, 0x72, 0x74, 0x4e, 0x61, 0x6d, 0x65, 0x18,
	0x1a, 0x20, 0x01, 0x28, 0x09, 0x52, 0x12, 0x44, 0x73, 0x74, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63,
	0x65, 0x50, 0x6f, 0x72, 0x74, 0x4e, 0x61, 0x6d, 0x65, 0x12, 0x2c, 0x0a, 0x11, 0x49, 0x6e, 0x67,
	0x72, 0x65, 0x73, 0x73, 0x50, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x4e, 0x61, 0x6d, 0x65, 0x18, 0x1d,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x11, 0x49, 0x6e, 0x67, 0x72, 0x65, 0x73, 0x73, 0x50, 0x6f, 0x6c,
	0x69, 0x63, 0x79, 0x4e, 0x61, 0x6d, 0x65, 0x12, 0x36, 0x0a, 0x16, 0x49, 0x6e, 0x67, 0x72, 0x65,
	0x73, 0x73, 0x50, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x4e, 0x61, 0x6d, 0x65, 0x73, 0x70, 0x61, 0x63,
	0x65, 0x18, 0x1e, 0x20, 0x01, 0x28, 0x09, 0x52, 0x16, 0x49, 0x6e, 0x67, 0x72, 0x65, 0x73, 0x73,
	0x50, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x4e, 0x61, 0x6d, 0x65, 0x73, 0x70, 0x61, 0x63, 0x65, 0x12,
	0x2a, 0x0a, 0x10, 0x45, 0x67, 0x72, 0x65, 0x73, 0x73, 0x50, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x4e,
	0x61, 0x6d, 0x65, 0x18, 0x1f, 0x20, 0x01, 0x28, 0x09, 0x52, 0x10, 0x45, 0x67, 0x72, 0x65, 0x73,
	0x73, 0x50, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x4e, 0x61, 0x6d, 0x65, 0x12, 0x34, 0x0a, 0x15, 0x45,
	0x67, 0x72, 0x65, 0x73, 0x73, 0x50, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x4e, 0x61, 0x6d, 0x65, 0x73,
	0x70, 0x61, 0x63, 0x65, 0x18, 0x20, 0x20, 0x01, 0x28, 0x09, 0x52, 0x15, 0x45, 0x67, 0x72, 0x65,
	0x73, 0x73, 0x50, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x4e, 0x61, 0x6d, 0x65, 0x73, 0x70, 0x61, 0x63,
	0x65, 0x42, 0x17, 0x5a, 0x15, 0x70, 0x6b, 0x67, 0x2f, 0x70, 0x72, 0x6f, 0x64, 0x75, 0x63, 0x65,
	0x72, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x33,
}

var (
	file_pkg_producer_protobuf_flow_proto_rawDescOnce sync.Once
	file_pkg_producer_protobuf_flow_proto_rawDescData = file_pkg_producer_protobuf_flow_proto_rawDesc
)

func file_pkg_producer_protobuf_flow_proto_rawDescGZIP() []byte {
	file_pkg_producer_protobuf_flow_proto_rawDescOnce.Do(func() {
		file_pkg_producer_protobuf_flow_proto_rawDescData = protoimpl.X.CompressGZIP(file_pkg_producer_protobuf_flow_proto_rawDescData)
	})
	return file_pkg_producer_protobuf_flow_proto_rawDescData
}

var file_pkg_producer_protobuf_flow_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_pkg_producer_protobuf_flow_proto_goTypes = []interface{}{
	(*FlowType1)(nil), // 0: github.com.vmware.goipfix.producer.protobuf.FlowType1
	(*FlowType2)(nil), // 1: github.com.vmware.goipfix.producer.protobuf.FlowType2
}
var file_pkg_producer_protobuf_flow_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_pkg_producer_protobuf_flow_proto_init() }
func file_pkg_producer_protobuf_flow_proto_init() {
	if File_pkg_producer_protobuf_flow_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_pkg_producer_protobuf_flow_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*FlowType1); i {
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
		file_pkg_producer_protobuf_flow_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*FlowType2); i {
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
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_pkg_producer_protobuf_flow_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   2,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_pkg_producer_protobuf_flow_proto_goTypes,
		DependencyIndexes: file_pkg_producer_protobuf_flow_proto_depIdxs,
		MessageInfos:      file_pkg_producer_protobuf_flow_proto_msgTypes,
	}.Build()
	File_pkg_producer_protobuf_flow_proto = out.File
	file_pkg_producer_protobuf_flow_proto_rawDesc = nil
	file_pkg_producer_protobuf_flow_proto_goTypes = nil
	file_pkg_producer_protobuf_flow_proto_depIdxs = nil
}
