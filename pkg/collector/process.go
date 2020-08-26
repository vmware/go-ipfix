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

	"k8s.io/klog"

	"github.com/vmware/go-ipfix/pkg/entities"
	"github.com/vmware/go-ipfix/pkg/registry"
)

type collectingProcess struct {
	// for each obsDomainID, there is a map of templates
	templatesMap map[uint32]map[uint16][]*templateField
	// templatesLock allows multiple readers or one writer at the same time
	templatesLock *sync.RWMutex
	// template lifetime
	templateTTL uint32
	// registries for decoding Information Element
	ianaRegistry   registry.Registry
	antreaRegistry registry.Registry
	// server information
	address net.Addr
	// maximum buffer size to read the record
	maxBufferSize uint16
	// chanel to receive stop information
	stopChan chan bool
	// packet list
	messages []*entities.Message
}

const AntreaEnterpriseID uint32 = 55829

type templateField struct {
	elementID     uint16
	elementLength uint16
	enterpriseID  uint32
}

func (cp *collectingProcess) decodePacket(packetBuffer *bytes.Buffer) (*entities.Message, error) {
	message := entities.Message{}
	setHeader := entities.SetHeader{}
	err := decode(packetBuffer, &message.Version, &message.BufferLength, &message.ExportTime, &message.SeqNumber, &message.ObsDomainID, &setHeader)
	if err != nil {
		return nil, fmt.Errorf("Error in decoding message: %v", err)
	}
	if message.Version != uint16(10) {
		return nil, fmt.Errorf("Collector only supports IPFIX (v10). Invalid version %d received.", message.Version)
	}
	if setHeader.ID == 2 {
		record, err := cp.decodeTemplateRecord(packetBuffer, message.ObsDomainID)
		if err != nil {
			return nil, fmt.Errorf("Error in decoding message: %v", err)
		}
		message.Set = record
	} else {
		record, err := cp.decodeDataRecord(packetBuffer, message.ObsDomainID, setHeader.ID)
		if err != nil {
			return nil, fmt.Errorf("Error in decoding message: %v", err)
		}
		message.Set = record
	}
	cp.messages = append(cp.messages, &message)
	return &message, nil
}

func (cp *collectingProcess) decodeTemplateRecord(templateBuffer *bytes.Buffer, obsDomainID uint32) (*entities.Set, error) {
	var templateID uint16
	var fieldCount uint16
	err := decode(templateBuffer, &templateID, &fieldCount)
	if err != nil {
		return nil, fmt.Errorf("Error in decoding message: %v", err)
	}
	fields := make([]*templateField, 0)
	buff := templateBuffer
	set := entities.NewSet(buff)
	set.CreateNewSet(entities.Template, templateID)


	for i := 0; i < int(fieldCount); i++ {
		field := templateField{}
		// check whether enterprise ID is 0 or not
		elementID := make([]byte, 2)
		err = decode(templateBuffer, &elementID, &field.elementLength)
		if err != nil {
			return nil, fmt.Errorf("Error in decoding message: %v", err)
		}
		indicator := elementID[0] >> 7
		if indicator != 1 {
			field.enterpriseID = uint32(0)
		} else {
			err = decode(templateBuffer, &field.enterpriseID)
			if err != nil {
				return nil, fmt.Errorf("Error in decoding message: %v", err)
			}
			elementID[0] = elementID[0] ^ 0x80
		}
		field.elementID = binary.BigEndian.Uint16(elementID)
		fields = append(fields, &field)
	}
	cp.addTemplate(obsDomainID, templateID, fields)
	return set, nil
}

func (cp *collectingProcess) decodeDataRecord(dataBuffer *bytes.Buffer, obsDomainID uint32, templateID uint16) (*entities.Set, error) {
	// make sure template exists
	_, err := cp.getTemplate(obsDomainID, templateID)
	if err != nil {
		return nil, fmt.Errorf("Template %d with obsDomainID %d does not exist", templateID, obsDomainID)
	}
	buff := bytes.Buffer{}
	set := entities.NewSet(&buff)
	set.CreateNewSet(entities.Data, templateID)

	// decode data record using template?

	return set, nil
}

func (cp *collectingProcess) addTemplate(obsDomainID uint32, templateID uint16, fields []*templateField) {
	cp.templatesLock.Lock()
	if _, exists := cp.templatesMap[obsDomainID]; !exists {
		cp.templatesMap[obsDomainID] = make(map[uint16][]*templateField)
	}
	cp.templatesMap[obsDomainID][templateID] = fields
	cp.templatesLock.Unlock()
	// template lifetime management
	if cp.address.Network() == "tcp" {
		return
	}

	// Handle udp template expiration
	if cp.templateTTL == 0 {
		cp.templateTTL = 1800 * 3 // Default value is 5400s
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
	if fields, exists := cp.templatesMap[obsDomainID][templateID]; exists {
		return fields, nil
	} else {
		return nil, fmt.Errorf("Template %d with obsDomainID %d does not exist.", templateID, obsDomainID)
	}
}

func (cp *collectingProcess) deleteTemplate(obsDomainID uint32, templateID uint16) {
	cp.templatesLock.Lock()
	defer cp.templatesLock.Unlock()
	delete(cp.templatesMap[obsDomainID], templateID)
}

func (cp *collectingProcess) getDataType(templateField *templateField) entities.IEDataType {
	var registry registry.Registry
	if templateField.enterpriseID == 0 { // IANA Registry
		registry = cp.ianaRegistry
	} else if templateField.enterpriseID == AntreaEnterpriseID { // Antrea Registry
		registry = cp.antreaRegistry
	}
	fieldName, err := registry.GetIENameFromID(templateField.elementID)
	if err != nil {
		klog.Errorf("Information Element with id %d cannot be found.", templateField.elementID)
		return 255
	}
	ie, _ := registry.GetInfoElement(fieldName)
	return ie.DataType
}

func decode(buffer io.Reader, output ...interface{}) error {
	var err error
	for _, out := range output {
		err = binary.Read(buffer, binary.BigEndian, out)
	}
	return err
}
