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

	"k8s.io/klog"

	"github.com/vmware/go-ipfix/pkg/entities"
	"github.com/vmware/go-ipfix/pkg/producer/convertor"
	"github.com/vmware/go-ipfix/pkg/producer/protobuf"
)

const FlowType2 string = "FlowType2"

// convertRecordToFlowType2 is to support the FlowType2 proto schema.
type convertRecordToFlowType2 struct{}

func RegisterFlowType2() convertor.IPFIXToKafkaConvertor {
	return &convertRecordToFlowType2{}
}

func (c *convertRecordToFlowType2) ConvertIPFIXMsgToFlowMsgs(msg *entities.Message) []*protobuf.FlowMessage {
	convertRecordToFlowMsg := func(msg *entities.Message, record entities.Record) *protobuf.FlowMessage {
		flowType2 := &protobuf.FlowType2{}
		flowType2.TimeReceived = msg.GetExportTime()
		flowType2.SequenceNumber = msg.GetSequenceNum()
		flowType2.ObsDomainID = msg.GetObsDomainID()
		flowType2.ExportAddress = msg.GetExportAddress()
		for _, ie := range record.GetOrderedElementList() {
			switch ie.Element.Name {
			case "flowStartSeconds":
				flowType2.TimeFlowStartInSecs = ie.Value.(uint32)
			case "flowEndSeconds":
				flowType2.TimeFlowEndInSecs = ie.Value.(uint32)
			case "sourceIPv4Address", "sourceIPv6Address":
				if flowType2.SrcIP != "" {
					klog.Warningf("Do not expect source IP: %v to be filled already", flowType2.SrcIP)
				}
				flowType2.SrcIP = ie.Value.(net.IP).String()
			case "destinationIPv4Address", "destinationIPv6Address":
				if flowType2.DstIP != "" {
					klog.Warningf("Do not expect destination IP: %v to be filled already", flowType2.DstIP)
				}
				flowType2.DstIP = ie.Value.(net.IP).String()
			case "sourceTransportPort":
				flowType2.SrcPort = uint32(ie.Value.(uint16))
			case "destinationTransportPort":
				flowType2.DstPort = uint32(ie.Value.(uint16))
			case "protocolIdentifier":
				flowType2.Proto = uint32(ie.Value.(uint8))
			case "packetTotalCount":
				flowType2.PacketsTotal = ie.Value.(uint64)
			case "octetTotalCount":
				flowType2.BytesTotal = ie.Value.(uint64)
			case "packetDeltaCount":
				flowType2.PacketsDelta = ie.Value.(uint64)
			case "octetDeltaCount":
				flowType2.BytesDelta = ie.Value.(uint64)
			case "reversePacketTotalCount":
				flowType2.ReversePacketsTotal = ie.Value.(uint64)
			case "reverseOctetTotalCount":
				flowType2.ReverseBytesTotal = ie.Value.(uint64)
			case "reversePacketDeltaCount":
				flowType2.ReversePacketsDelta = ie.Value.(uint64)
			case "reverseOctetDeltaCount":
				flowType2.ReverseBytesDelta = ie.Value.(uint64)
			case "sourcePodNamespace":
				flowType2.SrcPodNamespace = ie.Value.(string)
			case "sourcePodName":
				flowType2.SrcPodName = ie.Value.(string)
			case "sourceNodeName":
				flowType2.SrcNodeName = ie.Value.(string)
			case "destinationPodNamespace":
				flowType2.DstPodNamespace = ie.Value.(string)
			case "destinationPodName":
				flowType2.DstPodName = ie.Value.(string)
			case "destinationNodeName":
				flowType2.DstNodeName = ie.Value.(string)
			case "destinationClusterIPv4", "destinationClusterIPv6":
				if flowType2.DstClusterIP != "" {
					klog.Warningf("Do not expect destination cluster IP: %v to be filled already", flowType2.DstClusterIP)
				}
				flowType2.DstClusterIP = ie.Value.(net.IP).String()
			case "destinationServicePort":
				flowType2.DstServicePort = uint32(ie.Value.(uint16))
			case "destinationServicePortName":
				flowType2.DstServicePortName = ie.Value.(string)
			case "ingressNetworkPolicyName":
				flowType2.IngressPolicyName = ie.Value.(string)
			case "ingressNetworkPolicyNamespace":
				flowType2.IngressPolicyNamespace = ie.Value.(string)
			case "egressNetworkPolicyName":
				flowType2.EgressPolicyName = ie.Value.(string)
			case "egressNetworkPolicyNamespace":
				flowType2.EgressPolicyNamespace = ie.Value.(string)
			default:
				klog.Warningf("There is no field with name: %v in flow message (.proto schema)", ie.Element.Name)
			}
		}
		return &protobuf.FlowMessage{
			FlowType: &protobuf.FlowMessage_Flow2{Flow2: flowType2},
		}
	}
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
