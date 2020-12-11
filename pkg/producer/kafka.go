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

package producer

import (
	"github.com/Shopify/sarama"
	"github.com/golang/protobuf/proto"
	"k8s.io/klog"
	"net"

	"github.com/vmware/go-ipfix/pkg/entities"
	"github.com/vmware/go-ipfix/pkg/producer/protobuf"
)

var (
	KafkaConfigVersion sarama.KafkaVersion
)

type KafkaProducer struct {
	producer sarama.AsyncProducer
	topic    string
}

// convertIPFIXMsgToFlowMsgs converts data records in IPFIX message to flow messages
// in given proto schema.
func convertIPFIXMsgToFlowMsgs(msg *entities.Message) []*protobuf.FlowMessage {
	set := msg.GetSet()
	if set.GetSetType() == entities.Template {
		return nil
	}

	flowMsgs := make([]*protobuf.FlowMessage, 0)
	for _, record := range set.GetRecords() {
		flowMsg := &protobuf.FlowMessage{}
		flowMsg.TimeReceived = msg.GetExportTime()
		flowMsg.SequenceNumber = msg.GetSequenceNum()
		flowMsg.ObsDomainID = msg.GetObsDomainID()
		flowMsg.ExportAddress = msg.GetExportAddress()
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
		flowMsgs = append(flowMsgs, flowMsg)
	}
	return flowMsgs
}

func NewKafkaProducer(asyncProducer sarama.AsyncProducer, topic string) *KafkaProducer{
	return &KafkaProducer{
		producer: asyncProducer,
		topic:    topic,
	}
}

// InitKafkaProducer with broker addresses and other Kafka config parameters.
func InitKafkaProducer(addrs []string, topic string, logErrors bool) (*KafkaProducer, error) {
	kafkaConfig := sarama.NewConfig()
	kafkaConfig.Version = KafkaConfigVersion
	kafkaConfig.Producer.Return.Successes = false
	kafkaConfig.Producer.Return.Errors = logErrors

	asyncProducer, err := sarama.NewAsyncProducer(addrs, kafkaConfig)
	if err != nil {
		return nil, err
	}
	producer := NewKafkaProducer(asyncProducer, topic)

	// Capturing errors from Kafka sarama client
	if logErrors {
		go func() {
			for msg := range asyncProducer.Errors() {
				klog.Error(msg)
			}
		}()
	}

	return producer, nil
}

// SendFlowMessage takes in the flow message in proto schema, encodes it and sends
// it to on the producer channel.
func (kp *KafkaProducer) SendFlowMessage(msg *protobuf.FlowMessage) {
	buf := proto.NewBuffer([]byte{})
	if err := buf.EncodeMessage(msg); err != nil {
		klog.Errorf("Error when encoding flow message: %v", err)
		return
	}

	kp.producer.Input() <- &sarama.ProducerMessage{
		Topic: kp.topic,
		Value: sarama.ByteEncoder(buf.Bytes()),
	}
}

// Publish takes in a message channel as input and converts all the messages on
// the message channel to flow messages in proto schema. This function exits when
// the input message channel is closed.
func (kp *KafkaProducer) Publish(msgCh chan *entities.Message) {
	for msg := range msgCh {
		flowMsgs := convertIPFIXMsgToFlowMsgs(msg)
		for _, flowMsg := range flowMsgs {
			kp.SendFlowMessage(flowMsg)
		}
	}
}
