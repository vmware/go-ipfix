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
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"k8s.io/component-base/logs"
	"k8s.io/klog/v2"

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
	flowRecords    []string
	mutex          sync.Mutex
)

func initLoggingToFile(fs *pflag.FlagSet) {
	var err error

	_, err = fs.GetBool(logToStdErrFlag)
	if err != nil {
		// Should not happen. Return for safety.
		return
	}
}

func addIPFIXFlags(fs *pflag.FlagSet) {
	fs.StringVar(&IPFIXAddr, "ipfix.addr", "0.0.0.0", "IPFIX collector address")
	fs.Uint16Var(&IPFIXPort, "ipfix.port", 4739, "IPFIX collector port")
	fs.StringVar(&IPFIXTransport, "ipfix.transport", "tcp", "IPFIX collector transport layer")
}

func addIPFIXMessage(msg *entities.Message) {
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
				elem := ie.GetInfoElement()
				fmt.Fprintf(&buf, "    %s: len=%d (enterprise ID = %d) \n", elem.Name, elem.Len, elem.EnterpriseId)
			}
		}
	} else {
		fmt.Fprint(&buf, "DATA SET:\n")
		for i, record := range set.GetRecords() {
			fmt.Fprintf(&buf, "  DATA RECORD-%d:\n", i)
			for _, ie := range record.GetOrderedElementList() {
				elem := ie.GetInfoElement()
				switch elem.DataType {
				case entities.Unsigned8:
					fmt.Fprintf(&buf, "    %s: %v \n", elem.Name, ie.GetUnsigned8Value())
				case entities.Unsigned16:
					fmt.Fprintf(&buf, "    %s: %v \n", elem.Name, ie.GetUnsigned16Value())
				case entities.Unsigned32:
					fmt.Fprintf(&buf, "    %s: %v \n", elem.Name, ie.GetUnsigned32Value())
				case entities.Unsigned64:
					fmt.Fprintf(&buf, "    %s: %v \n", elem.Name, ie.GetUnsigned64Value())
				case entities.Signed8:
					fmt.Fprintf(&buf, "    %s: %v \n", elem.Name, ie.GetSigned8Value())
				case entities.Signed16:
					fmt.Fprintf(&buf, "    %s: %v \n", elem.Name, ie.GetSigned16Value())
				case entities.Signed32:
					fmt.Fprintf(&buf, "    %s: %v \n", elem.Name, ie.GetSigned32Value())
				case entities.Signed64:
					fmt.Fprintf(&buf, "    %s: %v \n", elem.Name, ie.GetSigned64Value())
				case entities.Float32:
					fmt.Fprintf(&buf, "    %s: %v \n", elem.Name, ie.GetFloat32Value())
				case entities.Float64:
					fmt.Fprintf(&buf, "    %s: %v \n", elem.Name, ie.GetFloat64Value())
				case entities.Boolean:
					fmt.Fprintf(&buf, "    %s: %v \n", elem.Name, ie.GetBooleanValue())
				case entities.DateTimeSeconds:
					fmt.Fprintf(&buf, "    %s: %v \n", elem.Name, ie.GetUnsigned32Value())
				case entities.DateTimeMilliseconds:
					fmt.Fprintf(&buf, "    %s: %v \n", elem.Name, ie.GetUnsigned64Value())
				case entities.DateTimeMicroseconds, entities.DateTimeNanoseconds:
					err := fmt.Errorf("API does not support micro and nano seconds types yet")
					fmt.Fprintf(&buf, "    %s: %v \n", elem.Name, err)
				case entities.MacAddress:
					fmt.Fprintf(&buf, "    %s: %v \n", elem.Name, ie.GetMacAddressValue())
				case entities.Ipv4Address, entities.Ipv6Address:
					fmt.Fprintf(&buf, "    %s: %v \n", elem.Name, ie.GetIPAddressValue())
				case entities.String:
					fmt.Fprintf(&buf, "    %s: %v \n", elem.Name, ie.GetStringValue())
				default:
					err := fmt.Errorf("API supports only valid information elements with datatypes given in RFC7011")
					fmt.Fprintf(&buf, "    %s: %v \n", elem.Name, err)
				}
			}
		}
	}
	mutex.Lock()
	defer mutex.Unlock()
	flowRecords = append(flowRecords, buf.String())
}

func signalHandler(stopCh chan struct{}, messageReceived chan *entities.Message) {
	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)

	for {
		select {
		case msg := <-messageReceived:
			addIPFIXMessage(msg)
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
	// Initialize collecting process
	cpInput := collector.CollectorInput{
		Address:       IPFIXAddr + ":" + strconv.Itoa(int(IPFIXPort)),
		Protocol:      IPFIXTransport,
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

	var server *http.Server
	// Start the HTTP server in a separate goroutine
	go func() {
		mux := http.NewServeMux()
		mux.HandleFunc("/records", flowRecordHandler)
		mux.HandleFunc("/reset", resetRecordHandler)

		server = &http.Server{
			Addr:              ":8080",
			Handler:           mux,
			ReadHeaderTimeout: 5 * time.Second,
		}

		klog.InfoS("Server listening on :8080")
		if err := server.ListenAndServe(); err != http.ErrServerClosed {
			klog.Fatalf("ListenAndServe error: %v", err)
		}
	}()

	stopCh := make(chan struct{})
	go signalHandler(stopCh, messageReceived)

	<-stopCh
	// Stop the collector process
	cp.Stop()
	klog.Info("Stopping IPFIX collector")
	// Create a context with a 5-second timeout
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// Attempt to gracefully shut down the server
	if err := server.Shutdown(shutdownCtx); err != nil {
		klog.ErrorS(err, "Error during server shutdown")
	} else {
		klog.InfoS("Server gracefully stopped")
	}
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
	logs.AddFlags(flags)
	return cmd
}

func flowRecordHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		mutex.Lock()
		defer mutex.Unlock()
		// Retrieve data
		klog.InfoS("Return flow records", "length", len(flowRecords))
		// Convert data to JSON
		responseData := map[string]interface{}{"flowRecords": flowRecords}
		jsonData, err := json.Marshal(responseData)
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		// Set response headers
		w.Header().Set("Content-Type", "application/json")
		// Write JSON response
		w.Write(jsonData)
	} else {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
	}
}

func resetRecordHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		mutex.Lock()
		defer mutex.Unlock()
		klog.InfoS("Reset flow records")
		flowRecords = []string{}
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "Flow records successfully reset")
	} else {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
	}
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
