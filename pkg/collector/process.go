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
	templatesLock *sync.RWMutex
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
	// workers to deal with clients (client address -> packet channel)
	workers map[string]*worker
}

type templateField struct {
	elementID     uint16
	elementLength uint16
	enterpriseID  uint32
}

func InitCollectingProcess(address net.Addr, maxBufferSize uint16, templateTTL uint32) (*collectingProcess, error) {
	collectProc := &collectingProcess{
		templatesMap:  make(map[uint32]map[uint16][]*templateField),
		templatesLock: &sync.RWMutex{},
		templateTTL:   templateTTL,
		address:       address,
		maxBufferSize: maxBufferSize,
		stopChan:      make(chan bool),
		messages:      make([]*entities.Message, 0),
		workers:       make(map[string]*worker),
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

func (cp *collectingProcess) decodePacket(packetBuffer *bytes.Buffer) (*entities.Message, error) {
	message := entities.Message{}
	var id, length uint16
	err := decode(packetBuffer, &message.Version, &message.BufferLength, &message.ExportTime, &message.SeqNumber, &message.ObsDomainID, &id, &length)
	if err != nil {
		return nil, fmt.Errorf("Error in decoding message: %v", err)
	}
	if message.Version != uint16(10) {
		return nil, fmt.Errorf("Collector only supports IPFIX (v10). Invalid version %d received.", message.Version)
	}
	if id == 2 {
		record, err := cp.decodeTemplateRecord(packetBuffer, message.ObsDomainID)
		if err != nil {
			return nil, fmt.Errorf("Error in decoding message: %v", err)
		}
		message.Record = record
	} else {
		record, err := cp.decodeDataRecord(packetBuffer, message.ObsDomainID, id)
		if err != nil {
			return nil, fmt.Errorf("Error in decoding message: %v", err)
		}
		message.Record = record
	}
	cp.messages = append(cp.messages, &message)
	return &message, nil
}

func (cp *collectingProcess) decodeTemplateRecord(templateBuffer *bytes.Buffer, obsDomainID uint32) (interface{}, error) {
	var templateID uint16
	var fieldCount uint16
	err := decode(templateBuffer, &templateID, &fieldCount)
	if err != nil {
		return nil, fmt.Errorf("Error in decoding message: %v", err)
	}
	elements := make([]*templateField, 0)
	templateMsg := entities.NewTemplateMessage()

	for i := 0; i < int(fieldCount); i++ {
		element := templateField{}
		// check whether enterprise ID is 0 or not
		elementID := make([]byte, 2)
		var elementLength uint16
		err = decode(templateBuffer, &elementID, &elementLength)
		if err != nil {
			return nil, fmt.Errorf("Error in decoding message: %v", err)
		}
		indicator := elementID[0] >> 7
		if indicator != 1 {
			element.elementID = binary.BigEndian.Uint16(elementID)
			element.enterpriseID = uint32(0)
			element.elementLength = elementLength
		} else {
			err = decode(templateBuffer, &element.enterpriseID)
			if err != nil {
				return nil, fmt.Errorf("Error in decoding message: %v", err)
			}
			elementID[0] = elementID[0] ^ 0x80
			element.elementID = binary.BigEndian.Uint16(elementID)
			element.elementLength = elementLength
		}
		templateMsg.AddInfoElement(element.enterpriseID, element.elementID)
		elements = append(elements, &element)
	}
	cp.addTemplate(obsDomainID, templateID, elements)
	return templateMsg, nil
}

func (cp *collectingProcess) decodeDataRecord(dataBuffer *bytes.Buffer, obsDomainID uint32, templateID uint16) (interface{}, error) {
	// make sure template exists
	template, err := cp.getTemplate(obsDomainID, templateID)
	if err != nil {
		return nil, fmt.Errorf("Template %d with obsDomainID %d does not exist", templateID, obsDomainID)
	}
	dataMsg := entities.NewDataMessage()
	for _, field := range template {
		var length int
		if field.elementLength == entities.VariableLength { // string
			length = getFieldLength(dataBuffer)
		} else {
			length = int(field.elementLength)
		}
		val := dataBuffer.Next(length)
		dataMsg.AddInfoElement(field.enterpriseID, field.elementID, val)
	}
	return dataMsg, nil
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

func decode(buffer io.Reader, output ...interface{}) error {
	var err error
	for _, out := range output {
		err = binary.Read(buffer, binary.BigEndian, out)
	}
	return err
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

// get string field length for data record
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
