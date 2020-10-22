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
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"

	"k8s.io/klog"

	"github.com/vmware/go-ipfix/pkg/entities"
	"github.com/vmware/go-ipfix/pkg/registry"
	"github.com/vmware/go-ipfix/pkg/util"
)

type collectingProcess struct {
	// for each obsDomainID, there is a map of templates
	templatesMap map[uint32]map[uint16][]*entities.InfoElement
	// templatesLock allows multiple readers or one writer at the same time
	templatesLock sync.RWMutex
	// template lifetime
	templateTTL uint32
	// server information
	address net.Addr
	// maximum buffer size to read the record
	maxBufferSize uint16
	// chanel to receive stop information
	stopChan chan bool
	// packet list
	messages []*entities.Message
	// maps each client to its client handler (required channels)
	clients map[string]*clientHandler
	// clientsLock allows multiple readers or one writer to access clients map at the same time
	clientsLock sync.RWMutex
}

type clientHandler struct {
	packetChan chan *bytes.Buffer
	errChan    chan bool
}

func InitCollectingProcess(address net.Addr, maxBufferSize uint16, templateTTL uint32) (*collectingProcess, error) {
	collectProc := &collectingProcess{
		templatesMap:  make(map[uint32]map[uint16][]*entities.InfoElement),
		templatesLock: sync.RWMutex{},
		templateTTL:   templateTTL,
		address:       address,
		maxBufferSize: maxBufferSize,
		stopChan:      make(chan bool),
		messages:      make([]*entities.Message, 0),
		clients:       make(map[string]*clientHandler),
	}
	return collectProc, nil
}

func (cp *collectingProcess) Start() {
	if cp.address.Network() == "tcp" {
		cp.startTCPServer()
	} else if cp.address.Network() == "udp" {
		cp.startUDPServer()
	}
}

func (cp *collectingProcess) Stop() {
	cp.stopChan <- true
}

func (cp *collectingProcess) GetMessages() []*entities.Message {
	return cp.messages
}

func (cp *collectingProcess) createClient() *clientHandler {
	return &clientHandler{
		packetChan: make(chan *bytes.Buffer),
		errChan:    make(chan bool),
	}
}

func (cp *collectingProcess) addClient(address string, client *clientHandler) {
	cp.clientsLock.Lock()
	defer cp.clientsLock.Unlock()
	cp.clients[address] = client
}

func (cp *collectingProcess) deleteClient(name string) {
	cp.clientsLock.Lock()
	defer cp.clientsLock.Unlock()
	delete(cp.clients, name)
}

func (cp *collectingProcess) getClientCount() int {
	cp.clientsLock.RLock()
	defer cp.clientsLock.RUnlock()
	return len(cp.clients)
}

func (cp *collectingProcess) decodePacket(packetBuffer *bytes.Buffer) (*entities.Message, error) {
	message := entities.Message{}
	var setID, length uint16
	err := util.Decode(packetBuffer, binary.BigEndian, &message.Version, &message.BufferLength, &message.ExportTime, &message.SeqNumber, &message.ObsDomainID, &setID, &length)
	if err != nil {
		return nil, err
	}
	if message.Version != uint16(10) {
		return nil, fmt.Errorf("Collector only supports IPFIX (v10). Invalid version %d received.", message.Version)
	}
	if setID == entities.TemplateSetID {
		set, err := cp.decodeTemplateSet(packetBuffer, message.ObsDomainID)
		if err != nil {
			return nil, fmt.Errorf("Error in decoding message: %v", err)
		}
		message.Set = set
	} else {
		set, err := cp.decodeDataSet(packetBuffer, message.ObsDomainID, setID)
		if err != nil {
			return nil, fmt.Errorf("Error in decoding message: %v", err)
		}
		message.Set = set
	}
	cp.messages = append(cp.messages, &message)
	return &message, nil
}

func (cp *collectingProcess) decodeTemplateSet(templateBuffer *bytes.Buffer, obsDomainID uint32) (entities.Set, error) {
	var templateID uint16
	var fieldCount uint16
	err := util.Decode(templateBuffer, binary.BigEndian, &templateID, &fieldCount)
	if err != nil {
		return nil, err
	}
	elementsWithValue := make([]*entities.InfoElementWithValue, 0)
	templateSet := entities.NewSet(entities.Template, templateID, true)

	for i := 0; i < int(fieldCount); i++ {
		var element *entities.InfoElement
		var enterpriseID uint32
		var elementID uint16
		// check whether enterprise ID is 0 or not
		elementid := make([]byte, 2)
		var elementLength uint16
		err = util.Decode(templateBuffer, binary.BigEndian, &elementid, &elementLength)
		if err != nil {
			return nil, err
		}
		isNonIANARegistry := elementid[0]>>7 == 1
		if !isNonIANARegistry {
			elementID = binary.BigEndian.Uint16(elementid)
			enterpriseID = registry.IANAEnterpriseID
			element, err = registry.GetInfoElementFromID(elementID, enterpriseID)
			if err != nil {
				return nil, err
			}
		} else {
			/*
				Encoding format for Enterprise-Specific Information Elements:
				 0                   1                   2                   3
				 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
				+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
				|1| Information Element id. = 15 | Field Length = 4  (16 bits)  |
				+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
				| Enterprise number (32 bits)                                   |
				+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
				1: 1 bit
				Information Element id: 15 bits
				Field Length: 16 bits
				Enterprise ID: 32 bits
				(Reference: https://tools.ietf.org/html/rfc7011#appendix-A.2.2)
			*/
			err = util.Decode(templateBuffer, binary.BigEndian, &enterpriseID)
			if err != nil {
				return nil, err
			}
			elementid[0] = elementid[0] ^ 0x80
			elementID = binary.BigEndian.Uint16(elementid)
			element, err = registry.GetInfoElementFromID(elementID, enterpriseID)
			if err != nil {
				return nil, err
			}
		}
		ie := entities.NewInfoElementWithValue(element, nil)
		elementsWithValue = append(elementsWithValue, ie)
	}
	templateSet.AddRecord(elementsWithValue, templateID)
	cp.addTemplate(obsDomainID, templateID, elementsWithValue)
	return templateSet, nil
}

func (cp *collectingProcess) decodeDataSet(dataBuffer *bytes.Buffer, obsDomainID uint32, templateID uint16) (entities.Set, error) {
	// make sure template exists
	template, err := cp.getTemplate(obsDomainID, templateID)
	if err != nil {
		return nil, fmt.Errorf("Template %d with obsDomainID %d does not exist", templateID, obsDomainID)
	}
	dataSet := entities.NewSet(entities.Data, templateID, true)

	for dataBuffer.Len() > 0 {
		elements := make([]*entities.InfoElementWithValue, 0)
		for _, element := range template {
			var length int
			if element.Len == entities.VariableLength { // string
				length = getFieldLength(dataBuffer)
			} else {
				length = int(element.Len)
			}
			val := dataBuffer.Next(length)
			ie := entities.NewInfoElementWithValue(element, bytes.NewBuffer(val))
			elements = append(elements, ie)
		}
		dataSet.AddRecord(elements, templateID)
	}
	return dataSet, nil
}

func (cp *collectingProcess) addTemplate(obsDomainID uint32, templateID uint16, elementsWithValue []*entities.InfoElementWithValue) {
	cp.templatesLock.Lock()
	if _, exists := cp.templatesMap[obsDomainID]; !exists {
		cp.templatesMap[obsDomainID] = make(map[uint16][]*entities.InfoElement)
	}
	elements := make([]*entities.InfoElement, 0)
	for _, elementWithValue := range elementsWithValue {
		elements = append(elements, elementWithValue.Element)
	}
	cp.templatesMap[obsDomainID][templateID] = elements
	cp.templatesLock.Unlock()
	// template lifetime management
	if cp.address.Network() == "tcp" {
		return
	}

	// Handle udp template expiration
	if cp.templateTTL == 0 {
		cp.templateTTL = entities.TemplateTTL // Default value
	}
	go func() {
		ticker := time.NewTicker(time.Duration(cp.templateTTL) * time.Second)
		defer ticker.Stop()
		select {
		case <-ticker.C:
			klog.Infof("Template with id %d, and obsDomainID %d is expired.", templateID, obsDomainID)
			cp.deleteTemplate(obsDomainID, templateID)
			break
		}
	}()
}

func (cp *collectingProcess) getTemplate(obsDomainID uint32, templateID uint16) ([]*entities.InfoElement, error) {
	cp.templatesLock.RLock()
	defer cp.templatesLock.RUnlock()
	if elements, exists := cp.templatesMap[obsDomainID][templateID]; exists {
		return elements, nil
	} else {
		return nil, fmt.Errorf("Template %d with obsDomainID %d does not exist.", templateID, obsDomainID)
	}
}

func (cp *collectingProcess) deleteTemplate(obsDomainID uint32, templateID uint16) {
	cp.templatesLock.Lock()
	defer cp.templatesLock.Unlock()
	delete(cp.templatesMap[obsDomainID], templateID)
}

// getMessageLength returns buffer length by decoding the header
func getMessageLength(msgBuffer *bytes.Buffer) (int, error) {
	packet := entities.Message{}
	var id, length uint16
	err := util.Decode(msgBuffer, binary.BigEndian, &packet.Version, &packet.BufferLength, &packet.ExportTime, &packet.SeqNumber, &packet.ObsDomainID, &id, &length)
	if err != nil {
		return 0, fmt.Errorf("Cannot decode message: %v", err)
	}
	return int(packet.BufferLength), nil
}

// getFieldLength returns string field length for data record
// (encoding reference: https://tools.ietf.org/html/rfc7011#appendix-A.5)
func getFieldLength(dataBuffer *bytes.Buffer) int {
	lengthBuff := dataBuffer.Next(1)
	var lengthOneByte uint8
	util.Decode(bytes.NewBuffer(lengthBuff), binary.BigEndian, &lengthOneByte)
	if lengthOneByte < 255 { // string length is less than 255
		return int(lengthOneByte)
	}
	var lengthTwoBytes uint16
	lengthBuff = dataBuffer.Next(2)
	util.Decode(bytes.NewBuffer(lengthBuff), binary.BigEndian, &lengthTwoBytes)
	return int(lengthTwoBytes)
}
