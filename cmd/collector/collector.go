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

package main

import (
	"bytes"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"k8s.io/component-base/logs"
	"k8s.io/klog"

	"github.com/vmware/go-ipfix/pkg/collector"
	"github.com/vmware/go-ipfix/pkg/entities"
	"github.com/vmware/go-ipfix/pkg/registry"
)

const (
	logToStdErrFlag = "logtostderr"
)

var (
	IPFIXAddr      string
	IPFIXPort      uint16
	IPFIXTransport string
)

func initLoggingToFile(fs *pflag.FlagSet) {
	var err error
	var logToStdErr bool

	logToStdErr, err = fs.GetBool(logToStdErrFlag)
	if err != nil {
		// Should not happen. Return for safety.
		return
	}
	if logToStdErr {
		// Logging to files is not enabled.
		return
	}
}

func addIPFIXFlags(fs *pflag.FlagSet) {
	fs.StringVar(&IPFIXAddr, "ipfix.addr", "", "IPFIX collector address")
	fs.Uint16Var(&IPFIXPort, "ipfix.port", 4739, "IPFIX collector port")
	fs.StringVar(&IPFIXTransport, "ipfix.transport", "tcp", "IPFIX collector transport layer")
}

func printIPFIXMessage(msg *entities.Message) {
	var buf bytes.Buffer
	fmt.Fprint(&buf, "\nIPFIX-HDR:\n")
	fmt.Fprintf(&buf, "  version: %v,  Message Length: %v\n", msg.GetVersion(), msg.GetMessageLen())
	fmt.Fprintf(&buf, "  Exported Time: %v (%v)\n", msg.GetExportTime(), time.Unix(int64(msg.GetExportTime()), 0))
	fmt.Fprintf(&buf, "  Sequence No.: %v,  Observation Domain ID: %v\n", msg.GetSequenceNum(), msg.GetObsDomainID())

	set := msg.GetSet()
	if set.GetSetType() == entities.Template {
		fmt.Fprint(&buf, "TEMPLATE SET:\n")
		for i, record := range set.GetRecords() {
			fmt.Fprintf(&buf, "  TEMPLATE RECORD-%d:\n", i)
			for _, ie := range record.GetOrderedElementList() {
				fmt.Fprintf(&buf, "    %s: len=%d (enterprise ID = %d) \n", ie.Element.Name, ie.Element.Len, ie.Element.EnterpriseId)
			}
		}
	} else {
		fmt.Fprint(&buf, "DATA SET:\n")
		for i, record := range set.GetRecords() {
			fmt.Fprintf(&buf, "  DATA RECORD-%d:\n", i)
			for _, ie := range record.GetOrderedElementList() {
				fmt.Fprintf(&buf, "    %s: %v \n", ie.Element.Name, ie.Value)
			}
		}
	}
	klog.Infof(buf.String())
}

func signalHandler(stopCh chan struct{}, messageReceived chan *entities.Message) {
	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)

	for {
		select {
		case msg := <-messageReceived:
			printIPFIXMessage(msg)
		case <-signalCh:
			close(stopCh)
			return
		}
	}
}

func run() error {
	klog.Info("Starting IPFIX collector")

	// Load the IPFIX global registry
	registry.LoadRegistry()

	var netAddr net.Addr
	var err error
	if IPFIXTransport == "tcp" {
		netAddr, err = net.ResolveTCPAddr("tcp", IPFIXAddr+":"+strconv.Itoa(int(IPFIXPort)))
		if err != nil {
			return err
		}
	} else if IPFIXTransport == "udp" {
		netAddr, err = net.ResolveUDPAddr("udp", IPFIXAddr+":"+strconv.Itoa(int(IPFIXPort)))
		if err != nil {
			return err
		}
	} else {
		return fmt.Errorf("input given ipfix.transport flag is not supported or valid")
	}
	// Initialize collecting process
	cpInput := collector.CollectorInput{
		Address:       netAddr,
		MaxBufferSize: 65535,
		TemplateTTL:   0,
		IsEncrypted:   false,
		ServerCert:    nil,
		ServerKey:     nil,
	}
	cp, err := collector.InitCollectingProcess(cpInput)
	if err != nil {
		return err
	}
	// Start listening to connections and receiving messages.
	messageReceived := make(chan *entities.Message)
	go func() {
		go cp.Start()
		msgChan := cp.GetMsgChan()
		for message := range msgChan {
			klog.Info("Processing IPFIX message")
			messageReceived <- message
		}
	}()

	stopCh := make(chan struct{})
	go signalHandler(stopCh, messageReceived)

	<-stopCh
	// Stop the collector process
	cp.Stop()
	klog.Info("Stopping IPFIX collector")
	return nil
}

func newCollectorCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:  "ipfix-collector",
		Long: "IPFIX collector to decode the exported flow records",
		Run: func(cmd *cobra.Command, args []string) {
			initLoggingToFile(cmd.Flags())
			if err := run(); err != nil {
				klog.Fatalf("Error when running IPFIX collector: %v", err)
			}
		},
	}
	flags := cmd.Flags()
	addIPFIXFlags(flags)
	// Install command line flags
	flags.AddGoFlagSet(flag.CommandLine)
	return cmd
}

func main() {
	logs.InitLogs()
	defer logs.FlushLogs()

	command := newCollectorCommand()
	if err := command.Execute(); err != nil {
		logs.FlushLogs()
		os.Exit(1)
	}
}
