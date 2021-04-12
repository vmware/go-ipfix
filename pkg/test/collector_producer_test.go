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

// +build integration

package test

import (
	"net"
	"testing"

	"github.com/Shopify/sarama"
	saramamock "github.com/Shopify/sarama/mocks"
	"github.com/stretchr/testify/assert"

	"github.com/vmware/go-ipfix/pkg/collector"
	"github.com/vmware/go-ipfix/pkg/producer"
	"github.com/vmware/go-ipfix/pkg/producer/convertor"
	convertortest "github.com/vmware/go-ipfix/pkg/producer/convertor/test"
	"github.com/vmware/go-ipfix/pkg/registry"
)

var (
	msg1InBytes = []byte{0x0, 0x0, 0x0, 0x58, 0xa, 0x56, 0x8, 0xac, 0xc9, 0xbb, 0x82, 0x6, 0x10,
		0x1, 0x18, 0x1, 0x28, 0xf0, 0xe0, 0xe7, 0xd7, 0x4, 0x32, 0x8, 0x31, 0x30, 0x2e,
		0x30, 0x2e, 0x30, 0x2e, 0x31, 0x3a, 0x8, 0x31, 0x30, 0x2e, 0x30, 0x2e, 0x30,
		0x2e, 0x32, 0x40, 0xd2, 0x9, 0x48, 0xae, 0x2c, 0x50, 0x6, 0x58, 0xe8, 0x7, 0x68,
		0xf4, 0x3, 0x78, 0x90, 0x3, 0x88, 0x1, 0xc8, 0x1, 0xb2, 0x1, 0x4, 0x70, 0x6f,
		0x64, 0x32, 0xca, 0x1, 0x7, 0x30, 0x2e, 0x30, 0x2e, 0x30, 0x2e, 0x30, 0x8a, 0x2,
		0x9, 0x31, 0x32, 0x37, 0x2e, 0x30, 0x2e, 0x30, 0x2e, 0x31}
	msg2InBytes = []byte{0x0, 0x0, 0x0, 0x5d, 0xa, 0x5b, 0x8, 0xf6, 0xc8, 0xbb, 0x82, 0x6, 0x10,
		0x1, 0x18, 0x1, 0x28, 0xc0, 0xf0, 0xe7, 0xd7, 0x4, 0x32, 0x8, 0x31, 0x30, 0x2e,
		0x30, 0x2e, 0x30, 0x2e, 0x31, 0x3a, 0x8, 0x31, 0x30, 0x2e, 0x30, 0x2e, 0x30,
		0x2e, 0x32, 0x40, 0xd2, 0x9, 0x48, 0xae, 0x2c, 0x50, 0x6, 0x58, 0xa0, 0x6, 0x68,
		0xf4, 0x3, 0x78, 0xac, 0x2, 0x88, 0x1, 0x96, 0x1, 0x9a, 0x1, 0x4, 0x70, 0x6f,
		0x64, 0x31, 0xca, 0x1, 0x8, 0x31, 0x30, 0x2e, 0x30, 0x2e, 0x30, 0x2e, 0x33, 0x8a,
		0x2, 0x9, 0x31, 0x32, 0x37, 0x2e, 0x30, 0x2e, 0x30, 0x2e, 0x31, 0x90, 0x2, 0x83,
		0x25}
)

func TestCollectorToProducer(t *testing.T) {
	// Initialize required objects.
	registry.LoadRegistry()
	convertor.ProtoSchemaConvertor = map[string]convertor.RegisterProtoSchema{
		convertortest.FlowType1: convertortest.RegisterFlowType1,
	}
	address, err := net.ResolveUDPAddr("udp", "0.0.0.0:4739")
	if err != nil {
		t.Error(err)
	}
	// Initialize collecting process
	cpInput := collector.CollectorInput{
		Address:       address.String(),
		Protocol:      address.Network(),
		MaxBufferSize: 1024,
		TemplateTTL:   0,
		IsEncrypted:   false,
		ServerCert:    nil,
		ServerKey:     nil,
	}
	cp, _ := collector.InitCollectingProcess(cpInput)
	// Create a mock Kafka producer
	kafkaConfig := sarama.NewConfig()
	kafkaConfig.Version = producer.KafkaConfigVersion
	kafkaConfig.Producer.Return.Successes = true
	kafkaConfig.Producer.Return.Errors = true

	mockProducer := saramamock.NewAsyncProducer(t, kafkaConfig)
	kafkaProducer := producer.NewKafkaProducer(mockProducer, "test-flow-msgs", convertortest.FlowType1)

	go cp.Start()
	waitForCollectorReady(t, cp)
	go func() {
		conn, err := net.DialUDP("udp", nil, address)
		if err != nil {
			t.Errorf("UDP Collecting Process does not start correctly.")
		}
		defer conn.Close()
		// Using the packets from collector_intermediate_test.go
		conn.Write(templatePacketIPv4)
		conn.Write(dataPacket1IPv4)
		conn.Write(dataPacket2IPv4)
	}()

	go func() {
		mockProducer.ExpectInputAndSucceed()
		mockProducer.ExpectInputAndSucceed()
		kafkaProducer.Publish(cp.GetMsgChan())
	}()

	kafkaMsg1 := <-mockProducer.Successes()
	kafkaMsg1InBytes, _ := kafkaMsg1.Value.Encode()
	assert.Equalf(t, msg1InBytes, kafkaMsg1InBytes, "kafka msg should be equal to expected bytes")
	kafkaMsg2 := <-mockProducer.Successes()
	kafkaMsg2InBytes, _ := kafkaMsg2.Value.Encode()
	assert.Equalf(t, msg2InBytes, kafkaMsg2InBytes, "kafka msg should be equal to expected bytes")

	cp.Stop()
	if err := mockProducer.Close(); err != nil {
		t.Fatal(err)
	}
}
