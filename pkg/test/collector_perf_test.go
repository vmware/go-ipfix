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

//go:build !race
// +build !race

package test

import (
	"flag"
	"net"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/klog/v2"

	"github.com/tushartathgur/go-ipfix/pkg/collector"
	"github.com/tushartathgur/go-ipfix/pkg/exporter"
	"github.com/tushartathgur/go-ipfix/pkg/registry"
)

func init() {
	// Load the global registry
	registry.LoadRegistry()
}

const (
	numOfExporters = 100
	numOfRecords   = 600
)

/*
    Sample output:
	go test -test.v -run=Benchmark -test.benchmem -bench=BenchmarkMultipleExportersToCollector -memprofile memprofile.out -cpuprofile profile.out

	goos: darwin
	goarch: amd64
	pkg: github.com/tushartathgur/go-ipfix/pkg/test
	cpu: Intel(R) Core(TM) i7-8750H CPU @ 2.20GHz
	BenchmarkMultipleExportersToCollector
	BenchmarkMultipleExportersToCollector-12               1        1512748429 ns/op        252000840 B/op   7821837 allocs/op
	PASS
	ok      github.com/tushartathgur/go-ipfix/pkg/test     1.847s
*/
// TODO: This should not be benchmark test if it is not run multiple times. Test should use "b.N".
func BenchmarkMultipleExportersToCollector(b *testing.B) {
	disableLogToStderr()
	ctrl := gomock.NewController(b)
	defer ctrl.Finish()
	collectorInput := collector.CollectorInput{
		Address:     "127.0.0.1:0",
		Protocol:    "tcp",
		TemplateTTL: 0,
	}
	cp, err := collector.InitCollectingProcess(collectorInput)
	if err != nil {
		b.Fatalf("cannot start collecting process on %s: %v", cp.GetAddress().String(), err)
	}
	go cp.Start()
	waitForCollectorStatus(b, cp, true)
	b.ResetTimer()
	for i := 0; i < numOfExporters; i++ {
		b.StartTimer()
		exporterInput := exporter.ExporterInput{
			CollectorAddress:    cp.GetAddress().String(),
			CollectorProtocol:   cp.GetAddress().Network(),
			ObservationDomainID: uint32(i),
		}
		exporter, err := exporter.InitExportingProcess(exporterInput)
		if err != nil {
			b.Errorf("cannot start exporting process: %v", err)
		}
		templateID := exporter.NewTemplateID()
		exporter.SendSet(createTemplateSet(templateID, false))
		for j := 0; j < numOfRecords-1; j++ {
			exporter.SendSet(createDataSet(templateID, true, false, false))
		}
		b.StopTimer()
		time.Sleep(time.Millisecond)
	}
	b.StartTimer()
	count := 0
	for range cp.GetMsgChan() {
		count++
		if count == numOfRecords*numOfExporters {
			cp.Stop()
			break
		}
	}
	waitForCollectorStatus(b, cp, false)
}

func disableLogToStderr() {
	klogFlagSet := flag.NewFlagSet("klog", flag.ContinueOnError)
	klog.InitFlags(klogFlagSet)
	klogFlagSet.Parse([]string{"-logtostderr=false"})
}

func waitForCollectorStatus(b *testing.B, cp *collector.CollectingProcess, checkReady bool) {
	checkConn := func() (bool, error) {
		if conn, err := net.Dial(cp.GetAddress().Network(), cp.GetAddress().String()); err != nil {
			if checkReady {
				return false, err
			} else {
				return true, nil
			}
		} else {
			if checkReady {
				conn.Close()
				return true, nil
			} else {
				return false, err
			}
		}
	}
	if err := wait.Poll(100*time.Millisecond, 500*time.Millisecond, checkConn); err != nil {
		b.Fatalf("cannot establish connection to %s", cp.GetAddress().String())
	}
}
