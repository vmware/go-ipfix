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

package consumer

import (
	"fmt"
	"strings"

	"github.com/Shopify/sarama"
	"google.golang.org/protobuf/proto"
	"k8s.io/klog/v2"
)

const msgDelimitLen = 4

type ConsumerInput struct {
	// KafkaBrokers is a string of addresses of Kafka broker systems
	KafkaBrokers      []string
	KafkaVersion      sarama.KafkaVersion
	KafkaTopic        string
	KafkaProtoSchema  proto.Message
	KafkaLogErrors    bool
	MsgDelimitWithLen bool
}

type KafkaConsumer struct {
	input       ConsumerInput
	stopChan    chan struct{}
	messageChan chan *sarama.ConsumerMessage
}

func NewKafkaConsumer(input ConsumerInput) *KafkaConsumer {
	return &KafkaConsumer{
		input:       input,
		messageChan: make(chan *sarama.ConsumerMessage),
	}
}

func (kc *KafkaConsumer) InitSaramaConsumer() error {
	config := sarama.NewConfig()
	config.Version = kc.input.KafkaVersion
	config.Consumer.Return.Errors = kc.input.KafkaLogErrors

	consumer, err := sarama.NewConsumer(kc.input.KafkaBrokers, config)
	if err != nil {
		return err
	}
	defer consumer.Close()

	partitionConsumer, err := consumer.ConsumePartition(kc.input.KafkaTopic, 0, sarama.OffsetNewest)
	if err != nil {
		return fmt.Errorf("error when getting partition consumer: %v", err)
	}
	defer partitionConsumer.Close()
	for {
		select {
		case msg := <-partitionConsumer.Messages():
			kc.messageChan <- msg
		case err := <-partitionConsumer.Errors():
			klog.Error(err)
		case <-kc.stopChan:
			return nil
		}
	}
}

func (kc *KafkaConsumer) GetMsgChan() chan *sarama.ConsumerMessage {
	return kc.messageChan
}

func (kc *KafkaConsumer) Stop() {
	close(kc.stopChan)
}

func (kc *KafkaConsumer) DecodeAndPrintMsg(msg *sarama.ConsumerMessage) error {
	value := msg.Value
	if kc.input.MsgDelimitWithLen {
		value = value[msgDelimitLen:]
	}
	message := kc.input.KafkaProtoSchema
	err := proto.Unmarshal(value, message)
	if err != nil {
		return fmt.Errorf("invalid message received: %v", err)
	}
	msgStr := fmt.Sprint(message)
	msgLog := strings.ReplaceAll(msgStr, "  ", "\n\t")
	klog.Infof("\nMessage received from topic %s, partition %d:\n\t%s", msg.Topic, msg.Partition, msgLog)
	return nil
}
