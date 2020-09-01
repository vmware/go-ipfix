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

package collector

import (
	"bytes"
	"io"
	"net"

	"k8s.io/klog/v2"

	"github.com/vmware/go-ipfix/pkg/entities"
)

func (cp *collectingProcess) startUDPServer() {
	s, err := net.ResolveUDPAddr("udp", cp.address.String())
	if err != nil {
		klog.Error(err)
		return
	}
	conn, err := net.ListenUDP("udp", s)
	if err != nil {
		klog.Error(err)
		return
	}
	klog.Infof("Start %s collecting process on %s", cp.address.Network(), cp.address.String())
	defer conn.Close()
	go func() {
		for {
			buff := make([]byte, cp.maxBufferSize)
			size, address, err := conn.ReadFromUDP(buff)
			if err != nil {
				if err == io.EOF {
					klog.Infof("Connection %s has been closed.", cp.address.String())
				} else {
					klog.Errorf("Error in collecting process: %v", err)
				}
				return
			}
			packet := make([]byte, size)
			copy(packet, buff)
			if _, exist := cp.workers[address.String()]; !exist {
				worker := createWorker(address.String(), cp.decodePacket)
				worker.start()
				cp.workers[address.String()] = worker
			}
			worker := cp.workers[address.String()]
			worker.packetChan <- bytes.NewBuffer(packet)
		}
	}()
	select {
	case <-cp.stopChan:
		// stop all the workers before closing collector
		for _, worker := range cp.workers {
			worker.stop()
		}
		return
	}
}

type worker struct {
	address    string
	packetChan chan *bytes.Buffer
	errChan    chan bool
	decodeFunc func(packet *bytes.Buffer) (*entities.Message, error)
}

func createWorker(address string, decodeFunc func(packet *bytes.Buffer) (*entities.Message, error)) *worker {
	return &worker{
		address:    address,
		packetChan: make(chan *bytes.Buffer),
		errChan:    make(chan bool),
		decodeFunc: decodeFunc,
	}
}

func (w *worker) start() {
	go func() {
		for {
			select {
			case <-w.errChan:
				return
			case packet := <-w.packetChan:
				// get the message here
				message, err := w.decodeFunc(packet)
				if err != nil {
					klog.Error(err)
					return
				}
				klog.Info(message)
			}
		}
	}()
}

func (w *worker) stop() {
	w.errChan <- true
}
