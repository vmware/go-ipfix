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
	"github.com/vmware/go-ipfix/pkg/kafka/producer/convertor"
	"github.com/vmware/go-ipfix/pkg/kafka/producer/protobuf"
)

// convertRecordToFlowType2 is to support the FlowType2 proto schema.
type convertRecordToFlowType2 struct{}

func NewFlowType2Convertor() convertor.IPFIXToKafkaConvertor {
	return &convertRecordToFlowType2{}
}

func (c *convertRecordToFlowType2) ConvertIPFIXMsgToFlowMsgs(msg *entities.Message) []protoreflect.Message {
	convertRecordToFlowMsg := func(msg *entities.Message, record entities.Record) protoreflect.Message {
		flowType2 := &protobuf.FlowType2{}
		flowType2.TimeReceived = msg.GetExportTime()
		flowType2.SequenceNumber = msg.GetSequenceNum()
		flowType2.ObsDomainID = msg.GetObsDomainID()
		flowType2.ExportAddress = msg.GetExportAddress()
		addAllFieldsToFlowType2(flowType2, record)
		return flowType2.ProtoReflect()
	}
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

func (c *convertRecordToFlowType2) ConvertIPFIXRecordToFlowMsg(record entities.Record) protoreflect.Message {
	// We add the fields from the record directly and do not add the fields from
	// the IPIFX message to flowType1 kafka flow message.
	flowType2 := &protobuf.FlowType2{}
	addAllFieldsToFlowType2(flowType2, record)

	return flowType2.ProtoReflect()
}

func addAllFieldsToFlowType2(flowMsg *protobuf.FlowType2, record entities.Record) {
	for _, ie := range record.GetOrderedElementList() {
		var ipVal net.IP
		var portVal uint16
		var protoVal uint8
		switch ie.GetName() {
		case "flowStartMilliseconds":
			flowMsg.TimeFlowStartInMilliSecs = ie.GetUnsigned64Value()
		case "flowEndMilliseconds":
			flowMsg.TimeFlowEndInMilliSecs = ie.GetUnsigned64Value()
		case "sourceIPv4Address", "sourceIPv6Address":
			if flowMsg.SrcIP != "" {
				klog.Warningf("Do not expect source IP: %v to be filled already", flowMsg.SrcIP)
			}
			ipVal = ie.GetIPAddressValue()
			flowMsg.SrcIP = ipVal.String()
		case "destinationIPv4Address", "destinationIPv6Address":
			if flowMsg.DstIP != "" {
				klog.Warningf("Do not expect destination IP: %v to be filled already", flowMsg.DstIP)
			}
			ipVal = ie.GetIPAddressValue()
			flowMsg.DstIP = ipVal.String()
		case "sourceTransportPort":
			portVal = ie.GetUnsigned16Value()
			flowMsg.SrcPort = uint32(portVal)
		case "destinationTransportPort":
			portVal = ie.GetUnsigned16Value()
			flowMsg.DstPort = uint32(portVal)
		case "protocolIdentifier":
			protoVal = ie.GetUnsigned8Value()
			flowMsg.Proto = uint32(protoVal)
		case "packetTotalCount":
			flowMsg.PacketsTotal = ie.GetUnsigned64Value()
		case "octetTotalCount":
			flowMsg.BytesTotal = ie.GetUnsigned64Value()
		case "packetDeltaCount":
			flowMsg.PacketsDelta = ie.GetUnsigned64Value()
		case "octetDeltaCount":
			flowMsg.BytesDelta = ie.GetUnsigned64Value()
		case "reversePacketTotalCount":
			flowMsg.ReversePacketsTotal = ie.GetUnsigned64Value()
		case "reverseOctetTotalCount":
			flowMsg.ReverseBytesTotal = ie.GetUnsigned64Value()
		case "reversePacketDeltaCount":
			flowMsg.ReversePacketsDelta = ie.GetUnsigned64Value()
		case "reverseOctetDeltaCount":
			flowMsg.ReverseBytesDelta = ie.GetUnsigned64Value()
		case "sourcePodNamespace":
			flowMsg.SrcPodNamespace = ie.GetStringValue()
		case "sourcePodName":
			flowMsg.SrcPodName = ie.GetStringValue()
		case "sourceNodeName":
			flowMsg.SrcNodeName = ie.GetStringValue()
		case "destinationPodNamespace":
			flowMsg.DstPodNamespace = ie.GetStringValue()
		case "destinationPodName":
			flowMsg.DstPodName = ie.GetStringValue()
		case "destinationNodeName":
			flowMsg.DstNodeName = ie.GetStringValue()
		case "destinationClusterIPv4", "destinationClusterIPv6":
			if flowMsg.DstClusterIP != "" {
				klog.Warningf("Do not expect destination cluster IP: %v to be filled already", flowMsg.DstClusterIP)
			}
			flowMsg.DstClusterIP = ie.GetIPAddressValue().String()
		case "destinationServicePort":
			flowMsg.DstServicePort = uint32(ie.GetUnsigned16Value())
		case "destinationServicePortName":
			flowMsg.DstServicePortName = ie.GetStringValue()
		case "ingressNetworkPolicyName":
			flowMsg.IngressPolicyName = ie.GetStringValue()
		case "ingressNetworkPolicyNamespace":
			flowMsg.IngressPolicyNamespace = ie.GetStringValue()
		case "egressNetworkPolicyName":
			flowMsg.EgressPolicyName = ie.GetStringValue()
		case "egressNetworkPolicyNamespace":
			flowMsg.EgressPolicyNamespace = ie.GetStringValue()
		default:
			klog.Warningf("There is no field with name: %v in flow message (.proto schema)", ie.GetName())
		}
	}
}
