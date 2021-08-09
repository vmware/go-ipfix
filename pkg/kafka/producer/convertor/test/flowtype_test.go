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

package test

import (
	"net"
	"testing"

	"github.com/Shopify/sarama"
	saramamock "github.com/Shopify/sarama/mocks"
	"github.com/stretchr/testify/assert"

	"github.com/vmware/go-ipfix/pkg/entities"
	"github.com/vmware/go-ipfix/pkg/kafka/producer"
	"github.com/vmware/go-ipfix/pkg/kafka/producer/convertor"
	"github.com/vmware/go-ipfix/pkg/registry"
	"github.com/vmware/go-ipfix/pkg/test"
)

func init() {
	registry.LoadRegistry()
}

func createMsgwithDataSet(t *testing.T, isV6 bool) *entities.Message {
	set := entities.NewSet(true)
	_ = set.PrepareSet(entities.Data, 256)
	elements := make([]entities.InfoElementWithValue, 0)

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
		var value []byte
		switch ieName {
		case "flowStartSeconds", "flowEndSeconds":
			// hardcoding it to initial epoch to make the test simple.
			value, _ = entities.EncodeToIEDataType(entities.DateTimeSeconds, uint32(0))
		case "sourceIPv4Address":
			value, _ = entities.EncodeToIEDataType(entities.Ipv4Address, net.IP{10, 0, 0, 1})
		case "sourceIPv6Address":
			value, _ = entities.EncodeToIEDataType(entities.Ipv6Address, net.ParseIP("2001:0:3238:DFE1:63::FEFB"))
		case "destinationIPv4Address":
			value, _ = entities.EncodeToIEDataType(entities.Ipv4Address, net.IP{10, 0, 0, 2})
		case "destinationIPv6Address":
			value, _ = entities.EncodeToIEDataType(entities.Ipv6Address, net.ParseIP("2001:0:3238:DFE1:63::FEFC"))
		case "sourceTransportPort":
			value, _ = entities.EncodeToIEDataType(entities.Unsigned16, uint16(1234))
		case "destinationTransportPort":
			value, _ = entities.EncodeToIEDataType(entities.Unsigned16, uint16(5678))
		case "protocolIdentifier":
			value, _ = entities.EncodeToIEDataType(entities.Unsigned8, uint8(6))
		case "packetTotalCount", "octetTotalCount", "packetDeltaCount", "octetDeltaCount":
			value, _ = entities.EncodeToIEDataType(entities.Unsigned64, uint64(1000))
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
		var value []byte
		switch ieName {
		case "reversePacketTotalCount", "reverseOctetTotalCount", "reversePacketDeltaCount", "reverseOctetDeltaCount":
			value, _ = entities.EncodeToIEDataType(entities.Unsigned64, uint64(50))
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
		var value []byte
		switch ieName {
		case "sourcePodNamespace":
			value, _ = entities.EncodeToIEDataType(entities.String, "podns1")
		case "sourcePodName":
			value, _ = entities.EncodeToIEDataType(entities.String, "pod1")
		case "sourceNodeName":
			value, _ = entities.EncodeToIEDataType(entities.String, "node1")
		case "destinationPodNamespace":
			value, _ = entities.EncodeToIEDataType(entities.String, "podns2")
		case "destinationPodName":
			value, _ = entities.EncodeToIEDataType(entities.String, "pod2")
		case "destinationNodeName":
			value, _ = entities.EncodeToIEDataType(entities.String, "node2")
		case "destinationClusterIPv4":
			value, _ = entities.EncodeToIEDataType(entities.Ipv4Address, net.IP{192, 168, 0, 1})
		case "destinationClusterIPv6":
			value, _ = entities.EncodeToIEDataType(entities.Ipv6Address, net.ParseIP("2001:0:3238:EFE1:63::FEFE"))
		case "destinationServicePort":
			value, _ = entities.EncodeToIEDataType(entities.Unsigned16, uint16(4739))
		case "destinationServicePortName":
			value, _ = entities.EncodeToIEDataType(entities.String, "svc1")
		case "ingressNetworkPolicyName", "ingressNetworkPolicyNamespace", "egressNetworkPolicyName", "egressNetworkPolicyNamespace":
			value, _ = entities.EncodeToIEDataType(entities.String, "")
		default:
			t.Fatalf("information element with name: %v is not present in the element list", ieName)
		}
		ieWithValue.Value = value
		elements = append(elements, ieWithValue)
	}
	if err := set.AddRecord(elements, 0, 256); err != nil {
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
	kafkaConfig.Version = sarama.DefaultVersion
	kafkaConfig.Producer.Return.Successes = true
	kafkaConfig.Producer.Return.Errors = true

	testInput := producer.ProducerInput{
		KafkaLogSuccesses: false,
		KafkaTopic:        "test-flow-msgs",
		KafkaVersion:      sarama.DefaultVersion,
	}

	tests := []struct {
		name                 string
		protoSchemaConvertor convertor.IPFIXToKafkaConvertor
		expectedMsg1         []byte
		expectedMsg2         []byte
	}{
		{
			"test-with-FlowType1",
			NewFlowType1Convertor(),
			test.Msg1ForFlowType1,
			test.Msg2ForFlowType1,
		},
		{
			"test-with-FlowType2",
			NewFlowType2Convertor(),
			test.Msg1ForFlowType2,
			test.Msg2ForFlowType2,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockSaramaProducer := saramamock.NewAsyncProducer(t, kafkaConfig)
			testInput.ProtoSchemaConvertor = tt.protoSchemaConvertor
			kafkaProducer, err := producer.NewKafkaProducer(testInput)
			assert.NoError(t, err)
			kafkaProducer.SetSaramaProducer(mockSaramaProducer)

			mockSaramaProducer.ExpectInputAndSucceed()
			mockSaramaProducer.ExpectInputAndSucceed()
			messageChan := make(chan *entities.Message)
			go func() {
				messageChan <- createMsgwithDataSet(t, false)
				messageChan <- createMsgwithDataSet(t, true)
				close(messageChan)
			}()

			kafkaProducer.PublishIPFIXMessages(messageChan)

			kafkaMsg1 := <-mockSaramaProducer.Successes()
			kafkaMsg1InBytes, _ := kafkaMsg1.Value.Encode()
			assert.Equalf(t, tt.expectedMsg1, kafkaMsg1InBytes, "kafka msg should be equal to expected bytes")
			kafkaMsg2 := <-mockSaramaProducer.Successes()
			kafkaMsg2InBytes, _ := kafkaMsg2.Value.Encode()
			assert.Equalf(t, tt.expectedMsg2, kafkaMsg2InBytes, "kafka msg should be equal to expected bytes")

			if err := mockSaramaProducer.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
