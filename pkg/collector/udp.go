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
	"net"
	"sync"
	"time"

	"k8s.io/klog"

	"github.com/vmware/go-ipfix/pkg/entities"
)

func (cp *CollectingProcess) startUDPServer() {
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
	var wg sync.WaitGroup
	defer conn.Close()
	go func() {
		for {
			buff := make([]byte, cp.maxBufferSize)
			size, address, err := conn.ReadFromUDP(buff)
			if err != nil {
				if size == 0 { // received stop collector message
					return
				}
				klog.Errorf("Error in collecting process: %v", err)
				return
			}
			klog.V(2).Infof("Receiving %d bytes from %s", size, address.String())
			cp.handleUDPClient(address, &wg)
			cp.clients[address.String()].packetChan <- bytes.NewBuffer(buff[0:size])
		}
	}()
	<-cp.stopChan
	// stop all the workers before closing collector
	cp.closeAllClients()
	wg.Wait()
}

func (cp *CollectingProcess) handleUDPClient(address net.Addr, wg *sync.WaitGroup) {
	if _, exist := cp.clients[address.String()]; !exist {
		client := cp.createClient()
		cp.addClient(address.String(), client)
		wg.Add(1)
		defer wg.Done()
		go func() {
			ticker := time.NewTicker(time.Duration(entities.TemplateRefreshTimeOut) * time.Second)
			for {
				select {
				case <-client.errChan:
					klog.Infof("Collecting process from %s has stopped.", address.String())
					return
				case <-ticker.C: // set timeout for udp connection
					klog.Errorf("UDP connection from %s timed out.", address.String())
					cp.deleteClient(address.String())
					return
				case packet := <-client.packetChan:
					// get the message here
					message, err := cp.decodePacket(packet, address.String())
					if err != nil {
						klog.Error(err)
						return
					}
					klog.V(4).Info(message)
					ticker.Stop()
					ticker = time.NewTicker(time.Duration(entities.TemplateRefreshTimeOut) * time.Second)
				}
			}
		}()
	}
}
