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
	"fmt"
	"io"
	"net"
	"sync"

	"k8s.io/klog"

	"github.com/vmware/go-ipfix/pkg/entities"
	"github.com/vmware/go-ipfix/pkg/registry"
)

type TCPCollectingProcess struct {
	collectingProcess
}

func InitTCPCollectingProcess(address net.Addr, maxBufferSize uint16) (*TCPCollectingProcess, error) {
	ianaReg := registry.NewIanaRegistry()
	antreaReg := registry.NewAntreaRegistry()
	ianaReg.LoadRegistry()
	antreaReg.LoadRegistry()
	collectProc := &TCPCollectingProcess{
		collectingProcess{
			templatesMap:   make(map[uint32]map[uint16][]*templateField),
			templatesLock:  &sync.RWMutex{},
			templateTTL:    0,
			ianaRegistry:   ianaReg,
			antreaRegistry: antreaReg,
			address:        address,
			maxBufferSize:  maxBufferSize,
			stopChan:       make(chan bool),
			messages:        make([]*entities.Message, 0),
		},
	}
	return collectProc, nil
}

func (cp *collectingProcess) Start() {
	listener, err := net.Listen("tcp", cp.address.String())
	if err != nil {
		klog.Errorf("Cannot start collecting process on %s: %v", cp.address.String(), err)
		return
	}

	klog.Infof("Start %s collecting process on %s", cp.address.Network(), cp.address.String())
	defer listener.Close()

	for {
		conn, err := listener.Accept()
		if err != nil {
			klog.Errorf("Cannot start collecting process on %s: %v", cp.address.String(), err)
			return
		}
		errChan := make(chan bool)
		go func() {
			cp.handleConnection(conn, cp.maxBufferSize, cp.address, errChan)
		}()
		select {
		case <-errChan:
			return
		}
	}
}

func (cp *collectingProcess) handleConnection(conn net.Conn, maxBufferSize uint16, address net.Addr, errChan chan bool) {
	for {
		select {
		case <-cp.stopChan:
			errChan <- true
			return
		default:
			buff := make([]byte, maxBufferSize)
			size, err := conn.Read(buff)
			if err != nil {
				if err == io.EOF {
					klog.Infof("TCP Connection %s has been closed.", address.String())
				} else {
					klog.Errorf("Error in collecting process: %v", err)
				}
				return
			}
			klog.Infof("Receiving %d bytes from %s", size, address.String())
			message := make([]byte, size)
			copy(message, buff[0:size])
			for size > 0 {
				length, err := getMessageLength(bytes.NewBuffer(message))
				if err != nil {
					klog.Error(err)
					return
				}
				size = size - length
				// get the packet here
				packet, err := cp.decodePacket(bytes.NewBuffer(message[0:length]))
				if err != nil {
					klog.Error(err)
					return
				}
				klog.Info(packet)
				message = message[length:]
			}
		}
	}
	conn.Close()
}

// get buffer length by decoding the header
func getMessageLength(msgBuffer *bytes.Buffer) (int, error) {
	packet := entities.Message{}
	var id, length uint16
	err := decode(msgBuffer, &packet.Version, &packet.BufferLength, &packet.ExportTime, &packet.SeqNumber, &packet.ObsDomainID, &id, &length)
	if err != nil {
		return 0, fmt.Errorf("Cannot decode message: %v", err)
	}
	return int(packet.BufferLength), nil
}
