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
	"bytes"
	"encoding/binary"
	"net"
	"testing"

	"github.com/Shopify/sarama"
	saramamock "github.com/Shopify/sarama/mocks"
	"github.com/stretchr/testify/assert"

	"github.com/vmware/go-ipfix/pkg/entities"
	"github.com/vmware/go-ipfix/pkg/registry"
	"github.com/vmware/go-ipfix/pkg/util"
)

var (
	// Hard coding the kafka msg in bytes. Need to figure out a way to generate this.
	msg1InBytes = []byte{0x0, 0x0, 0x0, 0x56, 0x10, 0x1, 0x18, 0xd2, 0x9, 0x32, 0x8,
		0x31, 0x30, 0x2e, 0x30, 0x2e, 0x30, 0x2e, 0x31, 0x3a, 0x8, 0x31, 0x30, 0x2e,
		0x30, 0x2e, 0x30, 0x2e, 0x32, 0x40, 0xd2, 0x9, 0x48, 0xae, 0x2c, 0x50, 0x6,
		0x58, 0xe8, 0x7, 0x60, 0xe8, 0x7, 0x68, 0xe8, 0x7, 0x70, 0xe8, 0x7, 0x78,
		0x32, 0x80, 0x1, 0x32, 0x88, 0x1, 0x32, 0x90, 0x1, 0x32, 0xca, 0x1, 0xb, 0x31,
		0x39, 0x32, 0x2e, 0x31, 0x36, 0x38, 0x2e, 0x30, 0x2e, 0x31, 0x8a, 0x2, 0x9,
		0x31, 0x32, 0x37, 0x2e, 0x30, 0x2e, 0x30, 0x2e, 0x31, 0x90, 0x2, 0x83, 0x25}
	msg2InBytes = []byte{0x0, 0x0, 0x0, 0x86, 0x10, 0x1, 0x18, 0xd2, 0x9, 0x32,
		0x19, 0x32, 0x30, 0x30, 0x31, 0x3a, 0x30, 0x3a, 0x33, 0x32, 0x33, 0x38,
		0x3a, 0x64, 0x66, 0x65, 0x31, 0x3a, 0x36, 0x33, 0x3a, 0x3a, 0x66, 0x65,
		0x66, 0x62, 0x3a, 0x19, 0x32, 0x30, 0x30, 0x31, 0x3a, 0x30, 0x3a, 0x33,
		0x32, 0x33, 0x38, 0x3a, 0x64, 0x66, 0x65, 0x31, 0x3a, 0x36, 0x33, 0x3a,
		0x3a, 0x66, 0x65, 0x66, 0x63, 0x40, 0xd2, 0x9, 0x48, 0xae, 0x2c, 0x50, 0x6,
		0x58, 0xe8, 0x7, 0x60, 0xe8, 0x7, 0x68, 0xe8, 0x7, 0x70, 0xe8, 0x7, 0x78,
		0x32, 0x80, 0x1, 0x32, 0x88, 0x1, 0x32, 0x90, 0x1, 0x32, 0xca, 0x1, 0x19,
		0x32, 0x30, 0x30, 0x31, 0x3a, 0x30, 0x3a, 0x33, 0x32, 0x33, 0x38, 0x3a, 0x65,
		0x66, 0x65, 0x31, 0x3a, 0x36, 0x33, 0x3a, 0x3a, 0x66, 0x65, 0x66, 0x65, 0x8a,
		0x2, 0x9, 0x31, 0x32, 0x37, 0x2e, 0x30, 0x2e, 0x30, 0x2e, 0x31, 0x90, 0x2,
		0x83, 0x25}
)

func init() {
	registry.LoadRegistry()
}

func createMsgwithDataSet(t *testing.T, isV6 bool) *entities.Message {
	set := entities.NewSet(entities.Data, 256, true)

	elements := make([]*entities.InfoElementWithValue, 0)
	ieNamesIANA := []string{
		"flowStartSeconds",
		"flowEndSeconds",
		"sourceTransportPort",
		"destinationTransportPort",
		"protocolIdentifier",
		"packetTotalCount",
		"octetTotalCount",
		"packetDeltaCount",
		"octetDeltaCount",
	}
	ieNamesV4IANA := []string{
		"sourceIPv4Address",
		"destinationIPv4Address",
	}
	ieNamesV6IANA := []string{
		"sourceIPv6Address",
		"destinationIPv6Address",
	}
	ieNamesIANAReverse := []string{
		"reversePacketTotalCount",
		"reverseOctetTotalCount",
		"reversePacketDeltaCount",
		"reverseOctetDeltaCount",
	}
	ieNamesAntrea := []string{
		"sourcePodName",
		"sourcePodNamespace",
		"sourceNodeName",
		"destinationPodName",
		"destinationPodNamespace",
		"destinationNodeName",
		"destinationServicePort",
		"destinationServicePortName",
		"ingressNetworkPolicyName",
		"ingressNetworkPolicyNamespace",
		"egressNetworkPolicyName",
		"egressNetworkPolicyNamespace",
	}
	ieNamesV4Antrea := []string{
		"destinationClusterIPv4",
	}
	ieNamesV6Antrea := []string{
		"destinationClusterIPv6",
	}
	if isV6 {
		ieNamesIANA = append(ieNamesIANA, ieNamesV6IANA...)
		ieNamesAntrea = append(ieNamesAntrea, ieNamesV6Antrea...)
	} else {
		ieNamesIANA = append(ieNamesIANA, ieNamesV4IANA...)
		ieNamesAntrea = append(ieNamesAntrea, ieNamesV4Antrea...)
	}
	for _, ieName := range ieNamesIANA {
		ie, err := registry.GetInfoElement(ieName, registry.IANAEnterpriseID)
		if err != nil {
			t.Fatalf("Error when fetching element with name %v: %v", ieName, err)
		}
		ieWithValue := entities.NewInfoElementWithValue(ie, nil)
		value := new(bytes.Buffer)
		switch ieName {
		case "flowStartSeconds", "flowEndSeconds":
			// hardcoding it to initial epoch to make the test simple.
			util.Encode(value, binary.BigEndian, uint32(0))
		case "sourceIPv4Address":
			util.Encode(value, binary.BigEndian, net.IP{10, 0, 0, 1})
		case "sourceIPv6Address":
			util.Encode(value, binary.BigEndian, net.ParseIP("2001:0:3238:DFE1:63::FEFB"))
		case "destinationIPv4Address":
			util.Encode(value, binary.BigEndian, net.IP{10, 0, 0, 2})
		case "destinationIPv6Address":
			util.Encode(value, binary.BigEndian, net.ParseIP("2001:0:3238:DFE1:63::FEFC"))
		case "sourceTransportPort":
			util.Encode(value, binary.BigEndian, uint16(1234))
		case "destinationTransportPort":
			util.Encode(value, binary.BigEndian, uint16(5678))
		case "protocolIdentifier":
			util.Encode(value, binary.BigEndian, uint8(6))
		case "packetTotalCount", "octetTotalCount", "packetDeltaCount", "octetDeltaCount":
			util.Encode(value, binary.BigEndian, uint64(1000))
		default:
			t.Fatalf("information element with name: %v is not present in the element list", ieName)
		}
		ieWithValue.Value = value
		elements = append(elements, ieWithValue)
	}

	for _, ieName := range ieNamesIANAReverse {
		ie, err := registry.GetInfoElement(ieName, registry.IANAReversedEnterpriseID)
		if err != nil {
			t.Fatalf("Error when fetching element with name %v: %v", ieName, err)
		}
		ieWithValue := entities.NewInfoElementWithValue(ie, nil)
		value := new(bytes.Buffer)
		switch ieName {
		case "reversePacketTotalCount", "reverseOctetTotalCount", "reversePacketDeltaCount", "reverseOctetDeltaCount":
			util.Encode(value, binary.BigEndian, uint64(50))
		default:
			t.Fatalf("information element with name: %v is not present in the element list", ieName)
		}
		ieWithValue.Value = value
		elements = append(elements, ieWithValue)
	}

	for _, ieName := range ieNamesAntrea {
		ie, err := registry.GetInfoElement(ieName, registry.AntreaEnterpriseID)
		if err != nil {
			t.Fatalf("Error when fetching element with name %v: %v", ieName, err)
		}
		ieWithValue := entities.NewInfoElementWithValue(ie, nil)
		value := new(bytes.Buffer)
		switch ieName {
		case "sourcePodNamespace":
			util.Encode(value, binary.BigEndian, "podns1")
		case "sourcePodName":
			util.Encode(value, binary.BigEndian, "pod1")
		case "sourceNodeName":
			util.Encode(value, binary.BigEndian, "node1")
		case "destinationPodNamespace":
			util.Encode(value, binary.BigEndian, "podns2")
		case "destinationPodName":
			util.Encode(value, binary.BigEndian, "pod2")
		case "destinationNodeName":
			util.Encode(value, binary.BigEndian, "node2")
		case "destinationClusterIPv4":
			util.Encode(value, binary.BigEndian, net.IP{192, 168, 0, 1})
		case "destinationClusterIPv6":
			util.Encode(value, binary.BigEndian, net.ParseIP("2001:0:3238:EFE1:63::FEFE"))
		case "destinationServicePort":
			util.Encode(value, binary.BigEndian, uint16(4739))
		case "destinationServicePortName":
			util.Encode(value, binary.BigEndian, "svc1")
		case "ingressNetworkPolicyName", "ingressNetworkPolicyNamespace", "egressNetworkPolicyName", "egressNetworkPolicyNamespace":
			util.Encode(value, binary.BigEndian, "")
		default:
			t.Fatalf("information element with name: %v is not present in the element list", ieName)
		}
		ieWithValue.Value = value
		elements = append(elements, ieWithValue)
	}
	if err := set.AddRecord(elements, 256); err != nil {
		t.Fatal("Error when adding elements to the record")
	}
	msg := entities.NewMessage(true)
	msg.SetVersion(10)
	msg.SetObsDomainID(uint32(1234))
	msg.SetSequenceNum(1)
	msg.SetMessageLen(32)
	msg.SetExportAddress("127.0.0.1")
	msg.AddSet(set)

	return msg
}

func TestKafkaProducer_Publish(t *testing.T) {
	kafkaConfig := sarama.NewConfig()
	kafkaConfig.Version = KafkaConfigVersion
	kafkaConfig.Producer.Return.Successes = true
	kafkaConfig.Producer.Return.Errors = true

	mockProducer := saramamock.NewAsyncProducer(t, kafkaConfig)
	kafkaProducer := NewKafkaProducer(mockProducer, "test-flow-msgs")

	messageChan := make(chan *entities.Message)
	mockProducer.ExpectInputAndSucceed()
	mockProducer.ExpectInputAndSucceed()

	go func() {
		messageChan <- createMsgwithDataSet(t, false)
		messageChan <- createMsgwithDataSet(t, true)
		close(messageChan)
	}()

	kafkaProducer.Publish(messageChan)

	kafkaMsg1 := <-mockProducer.Successes()
	kafkaMsg1InBytes, _ := kafkaMsg1.Value.Encode()
	assert.Equalf(t, kafkaMsg1InBytes, msg1InBytes, "kafka msg should be equal to expected bytes")
	kafkaMsg2 := <-mockProducer.Successes()
	kafkaMsg2InBytes, _ := kafkaMsg2.Value.Encode()
	assert.Equalf(t, kafkaMsg2InBytes, msg2InBytes, "kafka msg should be equal to expected bytes")

	if err := mockProducer.Close(); err != nil {
		t.Fatal(err)
	}
}
