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

	"k8s.io/klog/v2"

	"github.com/vmware/go-ipfix/pkg/entities"
	"github.com/vmware/go-ipfix/pkg/producer/convertor"
	"github.com/vmware/go-ipfix/pkg/producer/protobuf"
)

const FlowType1 string = "FlowType1"

// convertRecordToFlowType1 is to support the FlowType1 proto schema.
type convertRecordToFlowType1 struct{}

func RegisterFlowType1() convertor.IPFIXToKafkaConvertor {
	return &convertRecordToFlowType1{}
}

func (c *convertRecordToFlowType1) ConvertIPFIXMsgToFlowMsgs(msg *entities.Message) []*protobuf.FlowMessage {
	convertRecordToFlowMsg := func(msg *entities.Message, record entities.Record) *protobuf.FlowMessage {
		flowType1 := &protobuf.FlowType1{}
		flowType1.TimeReceived = msg.GetExportTime()
		flowType1.SequenceNumber = msg.GetSequenceNum()
		flowType1.ObsDomainID = msg.GetObsDomainID()
		flowType1.ExportAddress = msg.GetExportAddress()
		for _, ie := range record.GetOrderedElementList() {
			switch ie.Element.Name {
			case "flowStartSeconds":
				flowType1.TimeFlowStartInSecs = ie.Value.(uint32)
			case "flowEndSeconds":
				flowType1.TimeFlowEndInSecs = ie.Value.(uint32)
			case "sourceIPv4Address", "sourceIPv6Address":
				if flowType1.SrcIP != "" {
					klog.Warningf("Do not expect source IP: %v to be filled already", flowType1.SrcIP)
				}
				flowType1.SrcIP = ie.Value.(net.IP).String()
			case "destinationIPv4Address", "destinationIPv6Address":
				if flowType1.DstIP != "" {
					klog.Warningf("Do not expect destination IP: %v to be filled already", flowType1.DstIP)
				}
				flowType1.DstIP = ie.Value.(net.IP).String()
			case "sourceTransportPort":
				flowType1.SrcPort = uint32(ie.Value.(uint16))
			case "destinationTransportPort":
				flowType1.DstPort = uint32(ie.Value.(uint16))
			case "protocolIdentifier":
				flowType1.Proto = uint32(ie.Value.(uint8))
			case "packetTotalCount":
				flowType1.PacketsTotal = ie.Value.(uint64)
			case "octetTotalCount":
				flowType1.BytesTotal = ie.Value.(uint64)
			case "packetDeltaCount":
				flowType1.PacketsDelta = ie.Value.(uint64)
			case "octetDeltaCount":
				flowType1.BytesDelta = ie.Value.(uint64)
			case "reversePacketTotalCount":
				flowType1.ReversePacketsTotal = ie.Value.(uint64)
			case "reverseOctetTotalCount":
				flowType1.ReverseBytesTotal = ie.Value.(uint64)
			case "reversePacketDeltaCount":
				flowType1.ReversePacketsDelta = ie.Value.(uint64)
			case "reverseOctetDeltaCount":
				flowType1.ReverseBytesDelta = ie.Value.(uint64)
			case "sourcePodNamespace":
				flowType1.SrcPodNamespace = ie.Value.(string)
			case "sourcePodName":
				flowType1.SrcPodName = ie.Value.(string)
			case "sourceNodeName":
				flowType1.SrcNodeName = ie.Value.(string)
			case "destinationPodNamespace":
				flowType1.DstPodNamespace = ie.Value.(string)
			case "destinationPodName":
				flowType1.DstPodName = ie.Value.(string)
			case "destinationNodeName":
				flowType1.DstNodeName = ie.Value.(string)
			case "destinationClusterIPv4", "destinationClusterIPv6":
				if flowType1.DstClusterIP != "" {
					klog.Warningf("Do not expect destination cluster IP: %v to be filled already", flowType1.DstClusterIP)
				}
				flowType1.DstClusterIP = ie.Value.(net.IP).String()
			case "destinationServicePort":
				flowType1.DstServicePort = uint32(ie.Value.(uint16))
			case "destinationServicePortName":
				flowType1.DstServicePortName = ie.Value.(string)
			case "ingressNetworkPolicyName":
				flowType1.IngressPolicyName = ie.Value.(string)
			case "ingressNetworkPolicyNamespace":
				flowType1.IngressPolicyNamespace = ie.Value.(string)
			case "egressNetworkPolicyName":
				flowType1.EgressPolicyName = ie.Value.(string)
			case "egressNetworkPolicyNamespace":
				flowType1.EgressPolicyNamespace = ie.Value.(string)
			default:
				klog.Warningf("There is no field with name: %v in flow message (.proto schema)", ie.Element.Name)
			}
		}
		return &protobuf.FlowMessage{
			FlowType: &protobuf.FlowMessage_Flow1{Flow1: flowType1},
		}
	}
	// Convert all records in IPFIX set to Flow messages.
	set := msg.GetSet()
	if set.GetSetType() == entities.Template {
		return nil
	}
	records := set.GetRecords()
	flowMsgs := make([]*protobuf.FlowMessage, len(records))
	for i, record := range records {
		flowMsgs[i] = convertRecordToFlowMsg(msg, record)
	}
	return flowMsgs
}
