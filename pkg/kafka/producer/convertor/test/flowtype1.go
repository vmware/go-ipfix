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
		var err error
		var ipVal net.IP
		var portVal uint16
		var protoVal uint8
		element := ie.GetInfoElement()
		switch element.Name {
		case "flowStartSeconds":
			flowMsg.TimeFlowStartInSecs, err = ie.GetUnsigned32Value()
		case "flowEndSeconds":
			flowMsg.TimeFlowEndInSecs, err = ie.GetUnsigned32Value()
		case "sourceIPv4Address", "sourceIPv6Address":
			if flowMsg.SrcIP != "" {
				klog.Warningf("Do not expect source IP: %v to be filled already", flowMsg.SrcIP)
			}
			ipVal, err = ie.GetIPAddressValue()
			flowMsg.SrcIP = ipVal.String()
		case "destinationIPv4Address", "destinationIPv6Address":
			if flowMsg.DstIP != "" {
				klog.Warningf("Do not expect destination IP: %v to be filled already", flowMsg.DstIP)
			}
			ipVal, err = ie.GetIPAddressValue()
			flowMsg.DstIP = ipVal.String()
		case "sourceTransportPort":
			portVal, err = ie.GetUnsigned16Value()
			flowMsg.SrcPort = uint32(portVal)
		case "destinationTransportPort":
			portVal, err = ie.GetUnsigned16Value()
			flowMsg.DstPort = uint32(portVal)
		case "protocolIdentifier":
			protoVal, err = ie.GetUnsigned8Value()
			flowMsg.Proto = uint32(protoVal)
		case "packetTotalCount":
			flowMsg.PacketsTotal, err = ie.GetUnsigned64Value()
		case "octetTotalCount":
			flowMsg.BytesTotal, err = ie.GetUnsigned64Value()
		case "packetDeltaCount":
			flowMsg.PacketsDelta, err = ie.GetUnsigned64Value()
		case "octetDeltaCount":
			flowMsg.BytesDelta, err = ie.GetUnsigned64Value()
		case "reversePacketTotalCount":
			flowMsg.ReversePacketsTotal, err = ie.GetUnsigned64Value()
		case "reverseOctetTotalCount":
			flowMsg.ReverseBytesTotal, err = ie.GetUnsigned64Value()
		case "reversePacketDeltaCount":
			flowMsg.ReversePacketsDelta, err = ie.GetUnsigned64Value()
		case "reverseOctetDeltaCount":
			flowMsg.ReverseBytesDelta, err = ie.GetUnsigned64Value()
		case "sourcePodNamespace":
			flowMsg.SrcPodNamespace, err = ie.GetStringValue()
		case "sourcePodName":
			flowMsg.SrcPodName, err = ie.GetStringValue()
		case "sourceNodeName":
			flowMsg.SrcNodeName, err = ie.GetStringValue()
		case "destinationPodNamespace":
			flowMsg.DstPodNamespace, err = ie.GetStringValue()
		case "destinationPodName":
			flowMsg.DstPodName, err = ie.GetStringValue()
		case "destinationNodeName":
			flowMsg.DstNodeName, err = ie.GetStringValue()
		case "destinationClusterIPv4", "destinationClusterIPv6":
			if flowMsg.DstClusterIP != "" {
				klog.Warningf("Do not expect destination cluster IP: %v to be filled already", flowMsg.DstClusterIP)
			}
			ipVal, err = ie.GetIPAddressValue()
			flowMsg.DstClusterIP = ipVal.String()
		case "destinationServicePort":
			portVal, err = ie.GetUnsigned16Value()
			flowMsg.DstServicePort = uint32(portVal)
		case "destinationServicePortName":
			flowMsg.DstServicePortName, err = ie.GetStringValue()
		case "ingressNetworkPolicyName":
			flowMsg.IngressPolicyName, err = ie.GetStringValue()
		case "ingressNetworkPolicyNamespace":
			flowMsg.IngressPolicyNamespace, err = ie.GetStringValue()
		case "egressNetworkPolicyName":
			flowMsg.EgressPolicyName, err = ie.GetStringValue()
		case "egressNetworkPolicyNamespace":
			flowMsg.EgressPolicyNamespace, err = ie.GetStringValue()
		default:
			klog.Warningf("There is no field with name: %v in flow message (.proto schema)", element.Name)
		}
		if err != nil {
			klog.Errorf("Value format is different from expected in info element: %v", ie)
		}
	}
}
