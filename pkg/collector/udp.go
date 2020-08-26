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
	"github.com/vmware/go-ipfix/pkg/entities"
	"net"
	"sync"

	"k8s.io/klog"

	"github.com/vmware/go-ipfix/pkg/registry"
)

type UDPCollectingProcess struct {
	collectingProcess
	// list of udp workers to process message
	workerList []*Worker
	// udp worker pool to receive and process message
	workerPool chan chan *bytes.Buffer
	// number of workers
	workerNum int
}

func InitUDPCollectingProcess(address net.Addr, maxBufferSize uint16, workerNum int, templateTTL uint32) (*UDPCollectingProcess, error) {
	ianaReg := registry.NewIanaRegistry()
	antreaReg := registry.NewAntreaRegistry()
	ianaReg.LoadRegistry()
	antreaReg.LoadRegistry()
	workerList := make([]*Worker, workerNum)
	workerPool := make(chan chan *bytes.Buffer)
	collectProc := &UDPCollectingProcess{
		collectingProcess: collectingProcess{
			templatesMap:   make(map[uint32]map[uint16][]*templateField),
			templatesLock:  &sync.RWMutex{},
			templateTTL:    templateTTL,
			ianaRegistry:   ianaReg,
			antreaRegistry: antreaReg,
			address:        address,
			maxBufferSize:  maxBufferSize,
			stopChan:       make(chan bool),
			messages:        make([]*entities.Message, 0),
		},
		workerList: workerList,
		workerPool: workerPool,
		workerNum:  workerNum,
	}
	return collectProc, nil
}

func (cp *UDPCollectingProcess) Start() {
	cp.initWorkers(cp.workerNum)
	listener, err := net.ResolveUDPAddr(cp.address.Network(), cp.address.String())
	conn, err := net.ListenUDP("udp", listener)
	if err != nil {
		klog.Errorf("Cannot start collecting process on %s: %v", cp.address.String(), err)
	}

	klog.Infof("Start %s collecting process on %s", cp.address.Network(), cp.address.String())
	for {
		select {
		case <-cp.stopChan:
			cp.stopWorkers()
			return
		default:
			buff := make([]byte, cp.maxBufferSize)
			size, err := conn.Read(buff)
			if err != nil {
				klog.Errorf("Error in collecting process: %v", err)
				return
			}
			message := make([]byte, size)
			copy(message, buff[0:size])
			klog.Infof("Receiving %d bytes from %s", size, cp.address.String())
			cp.processMessage(message)
		}
	}
}

// Initialize and start all workers
func (cp *UDPCollectingProcess) initWorkers(workerNum int) {
	for i := 0; i < workerNum; i++ {
		worker := CreateWorker(i, cp.workerPool, cp.decodePacket)
		cp.workerList[i] = worker
	}
	for _, worker := range cp.workerList {
		worker.start()
	}
}

// Stop all workers
func (cp *UDPCollectingProcess) stopWorkers() {
	for _, worker := range cp.workerList {
		worker.stop()
	}
}

// Send message to worker pool
func (cp *UDPCollectingProcess) processMessage(message []byte) {
	messageChan := <-cp.workerPool
	messageChan <- bytes.NewBuffer(message)
}

type Worker struct {
	id          uint16
	messageChan chan *bytes.Buffer
	errorChan   chan bool
	workerPool  chan chan *bytes.Buffer
	decodeFunc  func(message *bytes.Buffer) (*entities.Message, error)
}

func CreateWorker(id int, workerPool chan chan *bytes.Buffer, decodeFunc func(message *bytes.Buffer) (*entities.Message, error)) *Worker {
	return &Worker{
		id:          uint16(id),
		messageChan: make(chan *bytes.Buffer),
		errorChan:   make(chan bool),
		workerPool:  workerPool,
		decodeFunc:  decodeFunc,
	}
}

// start a goroutine to process the message
func (worker *Worker) start() {
	go func() {
		for {
			select {
			case <-worker.errorChan:
				return
			case worker.workerPool <- worker.messageChan:
				message := <-worker.messageChan
				packet, err := worker.decodeFunc(message)
				if err != nil {
					klog.Errorf("Error in decoding message: %v", err)
				}
				klog.Infoln(packet)
			}
		}
	}()
}

func (worker *Worker) stop() {
	worker.errorChan <- true
}




