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
	"io"
	"net"
	"sync"
	"time"

	"k8s.io/klog/v2"

	"github.com/vmware/go-ipfix/pkg/config"
	"github.com/vmware/go-ipfix/pkg/entities"
)

type collectingProcess struct {
	// for each obsDomainID, there is a map of templates
	templatesMap map[uint32]map[uint16][]*templateField
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
	// channels to handle clients (address -> client)
	clients map[string]*clientHandler
}

type templateField struct {
	elementID     uint16
	elementLength uint16
	enterpriseID  uint32
}

type clientHandler struct {
	packetChan chan *bytes.Buffer
	errChan    chan bool
}

func InitCollectingProcess(address net.Addr, maxBufferSize uint16, templateTTL uint32) (*collectingProcess, error) {
	collectProc := &collectingProcess{
		templatesMap:  make(map[uint32]map[uint16][]*templateField),
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

func (cp *collectingProcess) createClient() *clientHandler {
	return &clientHandler{
		packetChan: make(chan *bytes.Buffer),
		errChan:    make(chan bool),
	}
}

func (cp *collectingProcess) deleteClient(name string) {
	delete(cp.clients, name)
}

func (cp *collectingProcess) getClientCount() int {
	return len(cp.clients)
}

func (cp *collectingProcess) decodePacket(packetBuffer *bytes.Buffer) (*entities.Message, error) {
	message := entities.Message{}
	var setID, length uint16
	err := decode(packetBuffer, &message.Version, &message.BufferLength, &message.ExportTime, &message.SeqNumber, &message.ObsDomainID, &setID, &length)
	if err != nil {
		return nil, fmt.Errorf("Error in decoding message: %v", err)
	}
	if message.Version != uint16(10) {
		return nil, fmt.Errorf("Collector only supports IPFIX (v10). Invalid version %d received.", message.Version)
	}
	if setID == config.TemplateSetID {
		record, err := cp.decodeTemplateSet(packetBuffer, message.ObsDomainID)
		if err != nil {
			return nil, fmt.Errorf("Error in decoding message: %v", err)
		}
		message.Record = record
	} else {
		record, err := cp.decodeDataSet(packetBuffer, message.ObsDomainID, setID)
		if err != nil {
			return nil, fmt.Errorf("Error in decoding message: %v", err)
		}
		message.Record = record
	}
	cp.messages = append(cp.messages, &message)
	return &message, nil
}

func (cp *collectingProcess) decodeTemplateSet(templateBuffer *bytes.Buffer, obsDomainID uint32) (interface{}, error) {
	var templateID uint16
	var fieldCount uint16
	err := decode(templateBuffer, &templateID, &fieldCount)
	if err != nil {
		return nil, fmt.Errorf("Error in decoding message: %v", err)
	}
	elements := make([]*templateField, 0)
	templateSet := entities.NewTemplateSet()

	for i := 0; i < int(fieldCount); i++ {
		element := templateField{}
		// check whether enterprise ID is 0 or not
		elementID := make([]byte, 2)
		var elementLength uint16
		err = decode(templateBuffer, &elementID, &elementLength)
		if err != nil {
			return nil, fmt.Errorf("Error in decoding message: %v", err)
		}
		isIANARegistry := elementID[0] >> 7
		if isIANARegistry != 1 {
			element.elementID = binary.BigEndian.Uint16(elementID)
			element.enterpriseID = uint32(0)
			element.elementLength = elementLength
		} else {
			err = decode(templateBuffer, &element.enterpriseID)
			if err != nil {
				return nil, fmt.Errorf("Error in decoding message: %v", err)
			}
			// encoding format: elementID[0] = elementID[0] | 0x80
			elementID[0] = elementID[0] ^ 0x80
			element.elementID = binary.BigEndian.Uint16(elementID)
			element.elementLength = elementLength
		}
		templateSet.AddInfoElement(element.enterpriseID, element.elementID)
		elements = append(elements, &element)
	}
	cp.addTemplate(obsDomainID, templateID, elements)
	return templateSet, nil
}

func (cp *collectingProcess) decodeDataSet(dataBuffer *bytes.Buffer, obsDomainID uint32, templateID uint16) (interface{}, error) {
	// make sure template exists
	template, err := cp.getTemplate(obsDomainID, templateID)
	if err != nil {
		return nil, fmt.Errorf("Template %d with obsDomainID %d does not exist", templateID, obsDomainID)
	}
	dataSet := entities.NewDataSet()
	for _, field := range template {
		var length int
		if field.elementLength == entities.VariableLength { // string
			length = getFieldLength(dataBuffer)
		} else {
			length = int(field.elementLength)
		}
		val := dataBuffer.Next(length)
		dataSet.AddInfoElement(field.enterpriseID, field.elementID, val)
	}
	return dataSet, nil
}

func (cp *collectingProcess) addTemplate(obsDomainID uint32, templateID uint16, elements []*templateField) {
	cp.templatesLock.Lock()
	if _, exists := cp.templatesMap[obsDomainID]; !exists {
		cp.templatesMap[obsDomainID] = make(map[uint16][]*templateField)
	}
	cp.templatesMap[obsDomainID][templateID] = elements
	cp.templatesLock.Unlock()
	// template lifetime management
	if cp.address.Network() == "tcp" {
		return
	}

	// Handle udp template expiration
	if cp.templateTTL == 0 {
		cp.templateTTL = config.TemplateTTL // Default value
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

func (cp *collectingProcess) getTemplate(obsDomainID uint32, templateID uint16) ([]*templateField, error) {
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

// decode decodes data from io reader to specified interfaces
func decode(buffer io.Reader, outputs ...interface{}) error {
	var err error
	for _, out := range outputs {
		err = binary.Read(buffer, binary.BigEndian, out)
	}
	return err
}

// getMessageLength returns buffer length by decoding the header
func getMessageLength(msgBuffer *bytes.Buffer) (int, error) {
	packet := entities.Message{}
	var id, length uint16
	err := decode(msgBuffer, &packet.Version, &packet.BufferLength, &packet.ExportTime, &packet.SeqNumber, &packet.ObsDomainID, &id, &length)
	if err != nil {
		return 0, fmt.Errorf("Cannot decode message: %v", err)
	}
	return int(packet.BufferLength), nil
}

// getFieldLength returns string field length for data record
func getFieldLength(dataBuffer *bytes.Buffer) int {
	lengthBuff := dataBuffer.Next(1)
	var length1 uint8
	decode(bytes.NewBuffer(lengthBuff), &length1)
	if length1 < 255 { // string length is less than 255
		return int(length1)
	}
	var length2 uint16
	lengthBuff = dataBuffer.Next(2)
	decode(bytes.NewBuffer(lengthBuff), &length2)
	return int(length2)
}
