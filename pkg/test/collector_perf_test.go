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
	"context"
	"flag"
	"net"
	"testing"
	"time"

	"go.uber.org/mock/gomock"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/klog/v2"

	"github.com/vmware/go-ipfix/pkg/collector"
	"github.com/vmware/go-ipfix/pkg/exporter"
)

const (
	numOfExporters = 100
	numOfRecords   = 1000
)

/*
    Sample output:
	go test -test.v -run=Benchmark -test.benchmem -bench=BenchmarkMultipleExportersToCollector -memprofile memprofile.out -cpuprofile profile.out

	goos: darwin
	goarch: amd64
	pkg: github.com/vmware/go-ipfix/pkg/test
	cpu: Intel(R) Core(TM) i7-8750H CPU @ 2.20GHz
	BenchmarkMultipleExportersToCollector
	BenchmarkMultipleExportersToCollector-12               1        1512748429 ns/op        252000840 B/op   7821837 allocs/op
	PASS
	ok      github.com/vmware/go-ipfix/pkg/test     1.847s
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
	exporters := make([]*exporter.ExportingProcess, 0, numOfExporters)
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
		exporters = append(exporters, exporter)
		time.Sleep(time.Millisecond)
	}
	b.StartTimer()
	count := 0
	for range cp.GetMsgChan() {
		count++
		if count == numOfRecords*numOfExporters {
			break
		}
	}
	b.StopTimer()
	// Gracefully shutdown all the exporters to avoid "use of closed network connection" error
	// logs.
	for i := 0; i < numOfExporters; i++ {
		exporters[i].CloseConnToCollector()
	}
	b.StartTimer()
	cp.Stop()
	waitForCollectorStatus(b, cp, false)
}

func BenchmarkCollector(b *testing.B) {
	bench := func(b *testing.B, isIPv6 bool) {
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
		exporterInput := exporter.ExporterInput{
			CollectorAddress:    cp.GetAddress().String(),
			CollectorProtocol:   cp.GetAddress().Network(),
			ObservationDomainID: 0,
		}
		exporter, err := exporter.InitExportingProcess(exporterInput)
		if err != nil {
			b.Errorf("cannot start exporting process: %v", err)
		}
		templateID := exporter.NewTemplateID()
		exporter.SendSet(createTemplateSet(templateID, isIPv6))
		dataSet := createDataSet(templateID, true, isIPv6, false)

		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			b.StopTimer()
			ch := make(chan struct{})
			go func() {
				count := 0
				for range cp.GetMsgChan() {
					count++
					if count == numOfRecords {
						close(ch)
						return
					}
				}
			}()
			b.StartTimer()
			for j := 0; j < numOfRecords; j++ {
				exporter.SendSet(dataSet)
			}
			<-ch
		}

		b.StopTimer()
		exporter.CloseConnToCollector()
		cp.Stop()
		waitForCollectorStatus(b, cp, false)
	}

	b.Run("ipv4", func(b *testing.B) { bench(b, false) })
	b.Run("ipv6", func(b *testing.B) { bench(b, true) })
}

func disableLogToStderr() {
	klogFlagSet := flag.NewFlagSet("klog", flag.ContinueOnError)
	klog.InitFlags(klogFlagSet)
	klogFlagSet.Parse([]string{"-logtostderr=false"})
}

func waitForCollectorStatus(b *testing.B, cp *collector.CollectingProcess, checkReady bool) {
	checkConn := func(ctx context.Context) (bool, error) {
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
	if err := wait.PollUntilContextTimeout(context.Background(), 100*time.Millisecond, 500*time.Millisecond, false, checkConn); err != nil {
		b.Fatalf("cannot establish connection to %s", cp.GetAddress().String())
	}
}
