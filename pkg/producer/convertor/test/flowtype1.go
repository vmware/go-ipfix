// Copyright 2021 VMware, Inc.
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

package test

import (
	"net"

	"google.golang.org/protobuf/reflect/protoreflect"
	"k8s.io/klog/v2"

	"github.com/vmware/go-ipfix/pkg/entities"
	"github.com/vmware/go-ipfix/pkg/producer/convertor"
	"github.com/vmware/go-ipfix/pkg/producer/protobuf"
)

// convertRecordToFlowType1 is to support the FlowType1 proto schema.
type convertRecordToFlowType1 struct{}

func NewFlowType1Convertor() convertor.IPFIXToKafkaConvertor {
	return &convertRecordToFlowType1{}
}

func (c *convertRecordToFlowType1) ConvertIPFIXMsgToFlowMsgs(msg *entities.Message) []protoreflect.Message {
	convertRecordToFlowMsg := func(msg *entities.Message, record entities.Record) protoreflect.Message {
		flowType1 := &protobuf.FlowType1{}
		flowType1.TimeReceived = msg.GetExportTime()
		flowType1.SequenceNumber = msg.GetSequenceNum()
		flowType1.ObsDomainID = msg.GetObsDomainID()
		flowType1.ExportAddress = msg.GetExportAddress()
		addAllFieldsToFlowType1(flowType1, record)
		return flowType1.ProtoReflect()
	}
	// Convert all records in IPFIX set to Flow messages.
	set := msg.GetSet()
	if set.GetSetType() == entities.Template {
		return nil
	}
	records := set.GetRecords()
	flowMsgs := make([]protoreflect.Message, len(records))
	for i, record := range records {
		flowMsgs[i] = convertRecordToFlowMsg(msg, record)
	}
	return flowMsgs
}

func (c *convertRecordToFlowType1) ConvertIPFIXRecordToFlowMsg(record entities.Record) protoreflect.Message {
	// We add the fields from the record directly and do not add the fields from
	// the IPIFX message to flowType1 kafka flow message.
	flowType1 := &protobuf.FlowType1{}
	addAllFieldsToFlowType1(flowType1, record)

	return flowType1.ProtoReflect()
}

func addAllFieldsToFlowType1(flowMsg *protobuf.FlowType1, record entities.Record) {
	for _, ie := range record.GetOrderedElementList() {
		switch ie.Element.Name {
		case "flowStartSeconds":
			flowMsg.TimeFlowStartInSecs = ie.Value.(uint32)
		case "flowEndSeconds":
			flowMsg.TimeFlowEndInSecs = ie.Value.(uint32)
		case "sourceIPv4Address", "sourceIPv6Address":
			if flowMsg.SrcIP != "" {
				klog.Warningf("Do not expect source IP: %v to be filled already", flowMsg.SrcIP)
			}
			flowMsg.SrcIP = ie.Value.(net.IP).String()
		case "destinationIPv4Address", "destinationIPv6Address":
			if flowMsg.DstIP != "" {
				klog.Warningf("Do not expect destination IP: %v to be filled already", flowMsg.DstIP)
			}
			flowMsg.DstIP = ie.Value.(net.IP).String()
		case "sourceTransportPort":
			flowMsg.SrcPort = uint32(ie.Value.(uint16))
		case "destinationTransportPort":
			flowMsg.DstPort = uint32(ie.Value.(uint16))
		case "protocolIdentifier":
			flowMsg.Proto = uint32(ie.Value.(uint8))
		case "packetTotalCount":
			flowMsg.PacketsTotal = ie.Value.(uint64)
		case "octetTotalCount":
			flowMsg.BytesTotal = ie.Value.(uint64)
		case "packetDeltaCount":
			flowMsg.PacketsDelta = ie.Value.(uint64)
		case "octetDeltaCount":
			flowMsg.BytesDelta = ie.Value.(uint64)
		case "reversePacketTotalCount":
			flowMsg.ReversePacketsTotal = ie.Value.(uint64)
		case "reverseOctetTotalCount":
			flowMsg.ReverseBytesTotal = ie.Value.(uint64)
		case "reversePacketDeltaCount":
			flowMsg.ReversePacketsDelta = ie.Value.(uint64)
		case "reverseOctetDeltaCount":
			flowMsg.ReverseBytesDelta = ie.Value.(uint64)
		case "sourcePodNamespace":
			flowMsg.SrcPodNamespace = ie.Value.(string)
		case "sourcePodName":
			flowMsg.SrcPodName = ie.Value.(string)
		case "sourceNodeName":
			flowMsg.SrcNodeName = ie.Value.(string)
		case "destinationPodNamespace":
			flowMsg.DstPodNamespace = ie.Value.(string)
		case "destinationPodName":
			flowMsg.DstPodName = ie.Value.(string)
		case "destinationNodeName":
			flowMsg.DstNodeName = ie.Value.(string)
		case "destinationClusterIPv4", "destinationClusterIPv6":
			if flowMsg.DstClusterIP != "" {
				klog.Warningf("Do not expect destination cluster IP: %v to be filled already", flowMsg.DstClusterIP)
			}
			flowMsg.DstClusterIP = ie.Value.(net.IP).String()
		case "destinationServicePort":
			flowMsg.DstServicePort = uint32(ie.Value.(uint16))
		case "destinationServicePortName":
			flowMsg.DstServicePortName = ie.Value.(string)
		case "ingressNetworkPolicyName":
			flowMsg.IngressPolicyName = ie.Value.(string)
		case "ingressNetworkPolicyNamespace":
			flowMsg.IngressPolicyNamespace = ie.Value.(string)
		case "egressNetworkPolicyName":
			flowMsg.EgressPolicyName = ie.Value.(string)
		case "egressNetworkPolicyNamespace":
			flowMsg.EgressPolicyNamespace = ie.Value.(string)
		default:
			klog.Warningf("There is no field with name: %v in flow message (.proto schema)", ie.Element.Name)
		}
	}
}
