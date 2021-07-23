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

package main

import (
	"flag"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Shopify/sarama"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/component-base/logs"
	"k8s.io/klog/v2"

	"github.com/vmware/go-ipfix/pkg/kafka/consumer"
	"github.com/vmware/go-ipfix/pkg/kafka/consumer/protobuf"
)

const (
	logToStdErrFlag = "logtostderr"
)

var (
	Brokers           string
	MsgDelimitWithLen bool
	KafkaTopic        string
)

func initLoggingToFile(fs *pflag.FlagSet) {
	var err error

	_, err = fs.GetBool(logToStdErrFlag)
	if err != nil {
		// Should not happen. Return for safety.
		return
	}
}

func addKafkaConsumerFlags(fs *pflag.FlagSet) {
	fs.StringVar(&Brokers, "brokers", "kafka-service:9092", "Kafka broker addresses delimited by comma")
	fs.BoolVar(&MsgDelimitWithLen, "consumer.delimitlen", false, "Kafka consumer message delimited with length")
	fs.StringVar(&KafkaTopic, "consumer.topic", "AntreaTopic", "Kafka topic")
}

func signalHandler(stopCh chan struct{}, consumer *consumer.KafkaConsumer) {
	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)

	for {
		select {
		case msg := <-consumer.GetMsgChan():
			consumer.DecodeAndPrintMsg(msg)
		case <-signalCh:
			close(stopCh)
			return
		}
	}
}

func run() error {
	klog.Info("Starting Kafka consumer")
	flowType := &protobuf.AntreaFlowMsg{}
	brokers := strings.Split(Brokers, ",")
	input := consumer.ConsumerInput{
		KafkaBrokers:      brokers,
		KafkaTopic:        KafkaTopic,
		MsgDelimitWithLen: MsgDelimitWithLen,
		KafkaProtoSchema:  flowType,
		KafkaVersion:      sarama.DefaultVersion,
		KafkaLogErrors:    true,
	}
	consumer := consumer.NewKafkaConsumer(input)
	go func() {
		err := wait.PollImmediateInfinite(500*time.Millisecond, func() (bool, error) {
			if err := consumer.InitSaramaConsumer(); err != nil {
				return false, nil
			} else {
				klog.Infof("Kafka consumer has run successfully")
				return true, nil
			}
		})
		if err != nil {
			klog.Error(err)
		}
		return
	}()

	stopCh := make(chan struct{})
	go signalHandler(stopCh, consumer)
	<-stopCh
	consumer.Stop()
	klog.Info("Stopping Kafka consumer")
	return nil
}

func newKafkaConsumerCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:  "kafka-consumer",
		Long: "Kafka consumer to collect and decode exported flow records",
		Run: func(cmd *cobra.Command, args []string) {
			initLoggingToFile(cmd.Flags())
			if err := run(); err != nil {
				klog.Fatalf("Error when running Kafka consumer: %v", err)
			}
		},
	}
	flags := cmd.Flags()
	addKafkaConsumerFlags(flags)
	// Install command line flags
	flags.AddGoFlagSet(flag.CommandLine)
	return cmd
}

func main() {
	logs.InitLogs()
	defer logs.FlushLogs()

	command := newKafkaConsumerCommand()
	if err := command.Execute(); err != nil {
		logs.FlushLogs()
		os.Exit(1)
	}
}
