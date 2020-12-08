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
	"strings"
	"sync"
	"time"

	"k8s.io/klog"

	"github.com/vmware/go-ipfix/pkg/entities"
	"github.com/vmware/go-ipfix/pkg/registry"
	"github.com/vmware/go-ipfix/pkg/util"
)

type CollectingProcess struct {
	// for each obsDomainID, there is a map of templates
	templatesMap map[uint32]map[uint16][]*entities.InfoElement
	// mutex allows multiple readers or one writer at the same time
	mutex sync.RWMutex
	// template lifetime
	templateTTL uint32
	// server information
	address net.Addr
	// maximum buffer size to read the record
	maxBufferSize uint16
	// chanel to receive stop information
	stopChan chan bool
	// messageChan is the channel to output message
	messageChan chan *entities.Message
	// maps each client to its client handler (required channels)
	clients map[string]*clientHandler
	// isEncrypted indicates whether to use TLS/DTLS for communication
	isEncrypted bool
	// caCert, serverCert and serverKey are for storing encryption info when using TLS/DTLS
	caCert     []byte
	serverCert []byte
	serverKey  []byte
}

type CollectorInput struct {
	Address       net.Addr
	MaxBufferSize uint16
	TemplateTTL   uint32
	IsEncrypted   bool
	// TODO: group following fields into struct to be reuse in exporter
	CACert     []byte
	ServerCert []byte
	ServerKey  []byte
}

type clientHandler struct {
	packetChan chan *bytes.Buffer
	errChan    chan bool
}

func InitCollectingProcess(input CollectorInput) (*CollectingProcess, error) {
	collectProc := &CollectingProcess{
		templatesMap:  make(map[uint32]map[uint16][]*entities.InfoElement),
		mutex:         sync.RWMutex{},
		templateTTL:   input.TemplateTTL,
		address:       input.Address,
		maxBufferSize: input.MaxBufferSize,
		stopChan:      make(chan bool),
		messageChan:   make(chan *entities.Message),
		clients:       make(map[string]*clientHandler),
		isEncrypted:   input.IsEncrypted,
		caCert:        input.CACert,
		serverCert:    input.ServerCert,
		serverKey:     input.ServerKey,
	}
	return collectProc, nil
}

func (cp *CollectingProcess) Start() {
	if cp.address.Network() == "tcp" {
		cp.startTCPServer()
	} else if cp.address.Network() == "udp" {
		cp.startUDPServer()
	}
}

func (cp *CollectingProcess) Stop() {
	cp.stopChan <- true
}

func (cp *CollectingProcess) GetAddress() net.Addr {
	cp.mutex.RLock()
	defer cp.mutex.RUnlock()
	return cp.address
}

func (cp *CollectingProcess) GetMsgChan() chan *entities.Message {
	return cp.messageChan
}

func (cp *CollectingProcess) CloseMsgChan() {
	cp.mutex.Lock()
	defer cp.mutex.Unlock()
	close(cp.messageChan)
}

func (cp *CollectingProcess) createClient() *clientHandler {
	return &clientHandler{
		packetChan: make(chan *bytes.Buffer),
		errChan:    make(chan bool),
	}
}

func (cp *CollectingProcess) addClient(address string, client *clientHandler) {
	cp.mutex.Lock()
	defer cp.mutex.Unlock()
	cp.clients[address] = client
}

func (cp *CollectingProcess) deleteClient(name string) {
	cp.mutex.Lock()
	defer cp.mutex.Unlock()
	delete(cp.clients, name)
}

func (cp *CollectingProcess) getClientCount() int {
	cp.mutex.RLock()
	defer cp.mutex.RUnlock()
	return len(cp.clients)
}

func (cp *CollectingProcess) closeAllClients() {
	cp.mutex.Lock()
	defer cp.mutex.Unlock()
	for _, client := range cp.clients {
		client.errChan <- true
	}
}

func (cp *CollectingProcess) decodePacket(packetBuffer *bytes.Buffer, exportAddress string) (*entities.Message, error) {
	var version, msgLen, setID, setLen uint16
	var exportTime, sequencNum, obsDomainID uint32
	err := util.Decode(packetBuffer, binary.BigEndian, &version, &msgLen, &exportTime, &sequencNum, &obsDomainID, &setID, &setLen)
	if err != nil {
		return nil, err
	}
	if version != uint16(10) {
		return nil, fmt.Errorf("collector only supports IPFIX (v10); invalid version %d received", version)
	}

	message := entities.NewMessage(true)
	message.SetVersion(version)
	message.SetMessageLen(msgLen)
	message.SetExportTime(exportTime)
	message.SetSequenceNum(sequencNum)
	message.SetObsDomainID(obsDomainID)
	message.SetExportAddress(strings.Split(exportAddress, ":")[0])

	var set entities.Set
	if setID == entities.TemplateSetID {
		set, err = cp.decodeTemplateSet(packetBuffer, obsDomainID)
		if err != nil {
			return nil, fmt.Errorf("error in decoding message: %v", err)
		}
	} else {
		set, err = cp.decodeDataSet(packetBuffer, obsDomainID, setID)
		if err != nil {
			return nil, fmt.Errorf("error in decoding message: %v", err)
		}
	}
	message.AddSet(set)

	// the thread(s)/client(s) executing the code will get blocked until the message is consumed/read in other goroutines.
	cp.messageChan <- message
	return message, nil
}

func (cp *CollectingProcess) decodeTemplateSet(templateBuffer *bytes.Buffer, obsDomainID uint32) (entities.Set, error) {
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

func (cp *CollectingProcess) decodeDataSet(dataBuffer *bytes.Buffer, obsDomainID uint32, templateID uint16) (entities.Set, error) {
	// make sure template exists
	template, err := cp.getTemplate(obsDomainID, templateID)
	if err != nil {
		return nil, fmt.Errorf("template %d with obsDomainID %d does not exist", templateID, obsDomainID)
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

func (cp *CollectingProcess) addTemplate(obsDomainID uint32, templateID uint16, elementsWithValue []*entities.InfoElementWithValue) {
	cp.mutex.Lock()
	defer cp.mutex.Unlock()
	if _, exists := cp.templatesMap[obsDomainID]; !exists {
		cp.templatesMap[obsDomainID] = make(map[uint16][]*entities.InfoElement)
	}
	elements := make([]*entities.InfoElement, 0)
	for _, elementWithValue := range elementsWithValue {
		elements = append(elements, elementWithValue.Element)
	}
	cp.templatesMap[obsDomainID][templateID] = elements
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

func (cp *CollectingProcess) getTemplate(obsDomainID uint32, templateID uint16) ([]*entities.InfoElement, error) {
	cp.mutex.RLock()
	defer cp.mutex.RUnlock()
	if elements, exists := cp.templatesMap[obsDomainID][templateID]; exists {
		return elements, nil
	} else {
		return nil, fmt.Errorf("template %d with obsDomainID %d does not exist", templateID, obsDomainID)
	}
}

func (cp *CollectingProcess) deleteTemplate(obsDomainID uint32, templateID uint16) {
	cp.mutex.Lock()
	defer cp.mutex.Unlock()
	delete(cp.templatesMap[obsDomainID], templateID)
}

func (cp *CollectingProcess) updateAddress(address net.Addr) {
	cp.mutex.Lock()
	defer cp.mutex.Unlock()
	cp.address = address
}

// getMessageLength returns buffer length by decoding the header
func getMessageLength(msgBuffer *bytes.Buffer) (int, error) {
	var version, msgLen, setID, setLen uint16
	var exportTime, sequencNum, obsDomainID uint32
	// We do not really need to decode whole header. Support an utility function
	// that decodes header based on the offset.
	err := util.Decode(msgBuffer, binary.BigEndian, &version, &msgLen, &exportTime, &sequencNum, &obsDomainID, &setID, &setLen)
	if err != nil {
		return 0, fmt.Errorf("cannot decode message: %v", err)
	}
	return int(msgLen), nil
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
