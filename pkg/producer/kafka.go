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
	"encoding/binary"

	"github.com/Shopify/sarama"
	"google.golang.org/protobuf/proto"
	"k8s.io/klog"

	"github.com/vmware/go-ipfix/pkg/entities"
	"github.com/vmware/go-ipfix/pkg/producer/convertor"
	"github.com/vmware/go-ipfix/pkg/producer/protobuf"
)

var (
	KafkaConfigVersion sarama.KafkaVersion
)

type KafkaProducer struct {
	producer             sarama.AsyncProducer
	topic                string
	protoSchemaConvertor convertor.IPFIXToKafkaConvertor
}

func NewKafkaProducer(asyncProducer sarama.AsyncProducer, topic string, schemaType string) *KafkaProducer {
	return &KafkaProducer{
		producer:             asyncProducer,
		topic:                topic,
		protoSchemaConvertor: convertor.ProtoSchemaConvertor[schemaType](),
	}
}

// InitKafkaProducer with broker addresses and other Kafka config parameters.
func InitKafkaProducer(addrs []string, topic string, protoSchema string, logErrors bool) (*KafkaProducer, error) {
	kafkaConfig := sarama.NewConfig()
	kafkaConfig.Version = KafkaConfigVersion
	kafkaConfig.Producer.Return.Successes = false
	kafkaConfig.Producer.Return.Errors = logErrors

	asyncProducer, err := sarama.NewAsyncProducer(addrs, kafkaConfig)
	if err != nil {
		return nil, err
	}
	producer := NewKafkaProducer(asyncProducer, topic, protoSchema)

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
// it to on the producer channel. If kafkaDelimitMsgWithLen is set to true, it will
// return  a length-prefixed encoded message.
func (kp *KafkaProducer) SendFlowMessage(msg *protobuf.FlowMessage, kafkaDelimitMsgWithLen bool) {
	bytes, err := proto.Marshal(msg)
	if err != nil {
		klog.Errorf("Error when encoding flow message: %v", err)
		return
	}
	if kafkaDelimitMsgWithLen {
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, uint32(len(bytes)))
		bytes = append(b, bytes...)
	}

	kp.producer.Input() <- &sarama.ProducerMessage{
		Topic: kp.topic,
		Value: sarama.ByteEncoder(bytes),
	}
}

// Publish takes in a message channel as input and converts all the messages on
// the message channel to flow messages in proto schema. This function exits when
// the input message channel is closed.
func (kp *KafkaProducer) Publish(msgCh chan *entities.Message) {
	for msg := range msgCh {
		flowMsgs := kp.protoSchemaConvertor.ConvertIPFIXMsgToFlowMsgs(msg)
		for _, flowMsg := range flowMsgs {
			kp.SendFlowMessage(flowMsg, true)
		}
	}
}
