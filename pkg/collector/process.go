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
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"k8s.io/klog/v2"

	"github.com/vmware/go-ipfix/pkg/entities"
	"github.com/vmware/go-ipfix/pkg/registry"
	"github.com/vmware/go-ipfix/pkg/util"
)

// DecodingMode specifies how unknown information elements (in templates) are handled when decoding.
// Unknown information elements are elements which are not part of the static registry included with
// the library.
// Note that regardless of the DecodingMode, data sets must always match the corresponding template.
type DecodingMode string

const (
	// DecodingModeStrict will cause decoding to fail when an unknown IE is encountered in a template.
	DecodingModeStrict DecodingMode = "Strict"
	// DecodingModeLenientKeepUnknown will accept unknown IEs in templates. When decoding the
	// corresponding field in a data record, the value will be preserved (as an octet array).
	DecodingModeLenientKeepUnknown DecodingMode = "LenientKeepUnknown"
	// DecodingModeLenientDropUnknown will accept unknown IEs in templates. When decoding the
	// corresponding field in a data record, the value will be dropped (information element will
	// not be present in the resulting Record). Be careful when using this mode as the IEs
	// included in the resulting Record will no longer match the received template.
	DecodingModeLenientDropUnknown DecodingMode = "LenientDropUnknown"
)

type template struct {
	ies         []*entities.InfoElement
	expiryTime  time.Time
	expiryTimer timer
}

type CollectingProcess struct {
	// for each obsDomainID, there is a map of templates
	templatesMap map[uint32]map[uint16]*template
	// mutex allows multiple readers or one writer at the same time
	mutex sync.RWMutex
	// template lifetime
	templateTTL time.Duration
	// server information
	address string
	// server protocol
	protocol string
	// server net address
	netAddress net.Addr
	// maximum buffer size to read the record
	maxBufferSize uint16
	// chanel to receive stop information
	stopChan chan struct{}
	// messageChan is the channel to output message
	messageChan chan *entities.Message
	// maps each client to its client handler (required channels)
	clients map[string]*clientHandler
	// isEncrypted indicates whether to use TLS/DTLS for communication
	isEncrypted bool
	// numExtraElements specifies number of elements that could be added after
	// decoding the IPFIX data packet.
	numExtraElements int
	// decodingMode specifies how unknown information elements (in templates) are handled when
	// decoding.
	decodingMode DecodingMode
	// caCert, serverCert and serverKey are for storing encryption info when using TLS/DTLS
	caCert               []byte
	serverCert           []byte
	serverKey            []byte
	wg                   sync.WaitGroup
	numOfRecordsReceived uint64
	// clock implementation: enables injecting a fake clock for testing
	clock clock
}

type CollectorInput struct {
	IsIPv6      bool
	IsEncrypted bool
	// Address needs to be provided in hostIP:port format.
	Address string
	// Protocol needs to be provided in lower case format.
	// We support "tcp" and "udp" protocols.
	Protocol      string
	MaxBufferSize uint16
	TemplateTTL   uint32
	// TODO: group following fields into struct to be reuse in exporter
	CACert           []byte
	ServerCert       []byte
	ServerKey        []byte
	NumExtraElements int
	// DecodingMode specifies how unknown information elements (in templates) are handled when
	// decoding. The default value is DecodingModeStrict for historical reasons. For most uses,
	// DecodingModeLenientKeepUnknown is the most appropriate mode.
	DecodingMode DecodingMode
}

type clientHandler struct {
	packetChan      chan *bytes.Buffer
	closeClientChan chan struct{}
}

func initCollectingProcess(input CollectorInput, clock clock) (*CollectingProcess, error) {
	templateTTLSeconds := input.TemplateTTL
	if input.Protocol == "udp" && templateTTLSeconds == 0 {
		templateTTLSeconds = entities.TemplateTTL
	}
	templateTTL := time.Duration(templateTTLSeconds) * time.Second
	decodingMode := input.DecodingMode
	if decodingMode == "" {
		decodingMode = DecodingModeStrict
	}
	klog.InfoS(
		"Initializing the collecting process",
		"encrypted", input.IsEncrypted, "address", input.Address, "protocol", input.Protocol, "maxBufferSize", input.MaxBufferSize,
		"templateTTL", templateTTL, "numExtraElements", input.NumExtraElements, "decodingMode", decodingMode,
	)
	cp := &CollectingProcess{
		templatesMap:     make(map[uint32]map[uint16]*template),
		mutex:            sync.RWMutex{},
		templateTTL:      templateTTL,
		address:          input.Address,
		protocol:         input.Protocol,
		maxBufferSize:    input.MaxBufferSize,
		stopChan:         make(chan struct{}),
		messageChan:      make(chan *entities.Message),
		clients:          make(map[string]*clientHandler),
		isEncrypted:      input.IsEncrypted,
		caCert:           input.CACert,
		serverCert:       input.ServerCert,
		serverKey:        input.ServerKey,
		numExtraElements: input.NumExtraElements,
		decodingMode:     decodingMode,
		clock:            clock,
	}
	return cp, nil
}

func InitCollectingProcess(input CollectorInput) (*CollectingProcess, error) {
	return initCollectingProcess(input, realClock{})
}

func (cp *CollectingProcess) Start() {
	klog.Info("Starting the collecting process")
	if cp.protocol == "tcp" {
		cp.startTCPServer()
	} else if cp.protocol == "udp" {
		cp.startUDPServer()
	}
}

func (cp *CollectingProcess) Stop() {
	close(cp.stopChan)
	// wait for all connections to be safely deleted and returned
	cp.wg.Wait()
	klog.Info("Stopped the collecting process")
}

func (cp *CollectingProcess) GetAddress() net.Addr {
	cp.mutex.RLock()
	defer cp.mutex.RUnlock()
	return cp.netAddress
}

func (cp *CollectingProcess) GetMsgChan() <-chan *entities.Message {
	return cp.messageChan
}

func (cp *CollectingProcess) CloseMsgChan() {
	close(cp.messageChan)
}

func (cp *CollectingProcess) GetNumRecordsReceived() int64 {
	cp.mutex.RLock()
	defer cp.mutex.RUnlock()
	return int64(cp.numOfRecordsReceived)
}

func (cp *CollectingProcess) GetNumConnToCollector() int64 {
	cp.mutex.RLock()
	defer cp.mutex.RUnlock()
	return int64(len(cp.clients))
}

func (cp *CollectingProcess) incrementNumRecordsReceived() {
	cp.mutex.Lock()
	defer cp.mutex.Unlock()
	cp.numOfRecordsReceived = cp.numOfRecordsReceived + 1
}

func (cp *CollectingProcess) decodePacket(packetBuffer *bytes.Buffer, exportAddress string) (*entities.Message, error) {
	var length, version, setID, setLen uint16
	var exportTime, sequencNum, obsDomainID uint32
	if err := util.Decode(packetBuffer, binary.BigEndian, &version, &length, &exportTime, &sequencNum, &obsDomainID, &setID, &setLen); err != nil {
		return nil, err
	}
	if version != uint16(10) {
		return nil, fmt.Errorf("collector only supports IPFIX (v10); invalid version %d received", version)
	}

	message := entities.NewMessage(true)
	message.SetVersion(version)
	message.SetMessageLen(length)
	message.SetExportTime(exportTime)
	message.SetSequenceNum(sequencNum)
	message.SetObsDomainID(obsDomainID)

	// handle IPv6 address which may involve []
	portIndex := strings.LastIndex(exportAddress, ":")
	exportAddress = exportAddress[:portIndex]
	exportAddress = strings.Replace(exportAddress, "[", "", -1)
	exportAddress = strings.Replace(exportAddress, "]", "", -1)
	message.SetExportAddress(exportAddress)

	var set entities.Set
	var err error
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
	cp.incrementNumRecordsReceived()
	return message, nil
}

func (cp *CollectingProcess) decodeTemplateSet(templateBuffer *bytes.Buffer, obsDomainID uint32) (entities.Set, error) {
	var templateID uint16
	var fieldCount uint16
	if err := util.Decode(templateBuffer, binary.BigEndian, &templateID, &fieldCount); err != nil {
		return nil, err
	}

	decodeField := func() (entities.InfoElementWithValue, error) {
		var element *entities.InfoElement
		var enterpriseID uint32
		var elementID uint16
		// check whether enterprise ID is 0 or not
		elementid := make([]byte, 2)
		var elementLength uint16
		err := util.Decode(templateBuffer, binary.BigEndian, &elementid, &elementLength)
		if err != nil {
			return nil, err
		}
		isNonIANARegistry := elementid[0]>>7 == 1
		if !isNonIANARegistry {
			elementID = binary.BigEndian.Uint16(elementid)
			enterpriseID = registry.IANAEnterpriseID
			element, err = registry.GetInfoElementFromID(elementID, enterpriseID)
			if err != nil {
				if cp.decodingMode == DecodingModeStrict {
					return nil, err
				}
				klog.InfoS("Template includes an information element that is not present in registry", "obsDomainID", obsDomainID, "templateID", templateID, "enterpriseID", enterpriseID, "elementID", elementID)
				element = entities.NewInfoElement("", elementID, entities.OctetArray, enterpriseID, elementLength)
			}
		} else {
			/*
				Encoding format for Enterprise-Specific Information Elements:
				 0                   1                   2                   3
				 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
				+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
				|1| Information element id. = 15 | Field Length = 4  (16 bits)  |
				+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
				| Enterprise number (32 bits)                                   |
				+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
				1: 1 bit
				Information element id: 15 bits
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
				if cp.decodingMode == DecodingModeStrict {
					return nil, err
				}
				klog.InfoS("Template includes an information element that is not present in registry", "obsDomainID", obsDomainID, "templateID", templateID, "enterpriseID", enterpriseID, "elementID", elementID)
				element = entities.NewInfoElement("", elementID, entities.OctetArray, enterpriseID, elementLength)
			}
		}

		return entities.DecodeAndCreateInfoElementWithValue(element, nil)
	}

	elementsWithValue, err := func() ([]entities.InfoElementWithValue, error) {
		elementsWithValue := make([]entities.InfoElementWithValue, int(fieldCount))
		for i := range fieldCount {
			elementWithValue, err := decodeField()
			if err != nil {
				return nil, err
			}
			elementsWithValue[i] = elementWithValue
		}
		return elementsWithValue, nil
	}()
	if err != nil {
		// Delete existing template (if one exists) from template map if the new one is invalid.
		// This is particularly useful for UDP collection, as there is no feedback mechanism
		// to let the sender know that the new template is invalid (while with TCP, we can close
		// the connection). If we keep the old template and the sender sends data records
		// which use the new template, we would try to decode them according to the old
		// template, which would cause issues.
		cp.deleteTemplate(obsDomainID, templateID)
		return nil, err
	}

	templateSet := entities.NewSet(true)
	if err := templateSet.PrepareSet(entities.Template, templateID); err != nil {
		return nil, err
	}
	if err := templateSet.AddRecordV2(elementsWithValue, templateID); err != nil {
		return nil, err
	}
	cp.addTemplate(obsDomainID, templateID, elementsWithValue)
	return templateSet, nil
}

func (cp *CollectingProcess) decodeDataSet(dataBuffer *bytes.Buffer, obsDomainID uint32, templateID uint16) (entities.Set, error) {
	// make sure template exists
	template, err := cp.getTemplateIEs(obsDomainID, templateID)
	if err != nil {
		return nil, fmt.Errorf("template %d with obsDomainID %d does not exist", templateID, obsDomainID)
	}
	dataSet := entities.NewSet(true)
	if err = dataSet.PrepareSet(entities.Data, templateID); err != nil {
		return nil, err
	}

	for dataBuffer.Len() > 0 {
		elements := make([]entities.InfoElementWithValue, 0, len(template)+cp.numExtraElements)
		for _, ie := range template {
			var length int
			if ie.Len == entities.VariableLength { // string / octet array
				length = getFieldLength(dataBuffer)
			} else {
				length = int(ie.Len)
			}
			element, err := entities.DecodeAndCreateInfoElementWithValue(ie, dataBuffer.Next(length))
			if err != nil {
				return nil, err
			}
			// A missing name means an unknown element was received
			if cp.decodingMode == DecodingModeLenientDropUnknown && ie.Name == "" {
				klog.V(5).InfoS("Dropping field for unknown information element", "obsDomainID", obsDomainID, "ie", ie)
				continue
			}
			elements = append(elements, element)
		}
		err = dataSet.AddRecordV2(elements, templateID)
		if err != nil {
			return nil, err
		}
	}
	return dataSet, nil
}

func (cp *CollectingProcess) addTemplate(obsDomainID uint32, templateID uint16, elementsWithValue []entities.InfoElementWithValue) {
	cp.mutex.Lock()
	defer cp.mutex.Unlock()
	if _, ok := cp.templatesMap[obsDomainID]; !ok {
		cp.templatesMap[obsDomainID] = make(map[uint16]*template)
	}
	elements := make([]*entities.InfoElement, 0)
	for _, elementWithValue := range elementsWithValue {
		elements = append(elements, elementWithValue.GetInfoElement())
	}
	tpl, ok := cp.templatesMap[obsDomainID][templateID]
	if !ok {
		tpl = &template{}
		cp.templatesMap[obsDomainID][templateID] = tpl
	}
	tpl.ies = elements
	klog.V(4).InfoS("Added template to template map", "obsDomainID", obsDomainID, "templateID", templateID)
	// Template lifetime management for UDP.
	if cp.protocol != "udp" {
		return
	}
	tpl.expiryTime = cp.clock.Now().Add(cp.templateTTL)
	if tpl.expiryTimer == nil {
		tpl.expiryTimer = cp.clock.AfterFunc(cp.templateTTL, func() {
			klog.Infof("Template with id %d, and obsDomainID %d is expired.", templateID, obsDomainID)
			now := cp.clock.Now()
			// From the Go documentation:
			//   For a func-based timer created with AfterFunc(d, f), Reset either
			//   reschedules when f will run, in which case Reset returns true, or
			//   schedules f to run again, in which case it returns false. When Reset
			//   returns false, Reset neither waits for the prior f to complete before
			//   returning nor does it guarantee that the subsequent goroutine running f
			//   does not run concurrently with the prior one. If the caller needs to
			//   know whether the prior execution of f is completed, it must coordinate
			//   with f explicitly.
			// In our case, when f executes, we have to verify that the record is indeed
			// scheduled for deletion by checking expiryTime. We cannot just
			// automatically delete the template.
			cp.deleteTemplateWithConds(obsDomainID, templateID, func(tpl *template) bool {
				// lock will be held when this executes
				return !tpl.expiryTime.After(now)
			})
		})
	} else {
		tpl.expiryTimer.Reset(cp.templateTTL)
	}
}

// deleteTemplate returns true iff a template was actually deleted.
func (cp *CollectingProcess) deleteTemplate(obsDomainID uint32, templateID uint16) bool {
	return cp.deleteTemplateWithConds(obsDomainID, templateID)
}

// deleteTemplateWithConds returns true iff a template was actually deleted.
func (cp *CollectingProcess) deleteTemplateWithConds(obsDomainID uint32, templateID uint16, condFns ...func(*template) bool) bool {
	cp.mutex.Lock()
	defer cp.mutex.Unlock()
	template, ok := cp.templatesMap[obsDomainID][templateID]
	if !ok {
		return false
	}
	for _, condFn := range condFns {
		if !condFn(template) {
			return false
		}
	}
	// expiryTimer will be nil when the protocol is TCP.
	if template.expiryTimer != nil {
		// expiryTimer may have been stopped already (if the timer
		// expired and is the reason why the template is being deleted),
		// but it is safe to call Stop() on an expired timer.
		template.expiryTimer.Stop()
	}
	delete(cp.templatesMap[obsDomainID], templateID)
	klog.V(4).InfoS("Deleted template from template map", "obsDomainID", obsDomainID, "templateID", templateID)
	if len(cp.templatesMap[obsDomainID]) == 0 {
		delete(cp.templatesMap, obsDomainID)
		klog.V(4).InfoS("No more templates for observation domain", "obsDomainID", obsDomainID)
	}
	return true
}

func (cp *CollectingProcess) getTemplateIEs(obsDomainID uint32, templateID uint16) ([]*entities.InfoElement, error) {
	cp.mutex.RLock()
	defer cp.mutex.RUnlock()
	if template, ok := cp.templatesMap[obsDomainID][templateID]; ok {
		return template.ies, nil
	} else {
		return nil, fmt.Errorf("template %d with obsDomainID %d does not exist", templateID, obsDomainID)
	}
}

func (cp *CollectingProcess) updateAddress(address net.Addr) {
	cp.mutex.Lock()
	defer cp.mutex.Unlock()
	cp.netAddress = address
}

// getMessageLength returns buffer length by decoding the header
func getMessageLength(reader *bufio.Reader) (int, error) {
	partialHeader, err := reader.Peek(4)
	if err != nil {
		return 0, err
	}
	var msgLen uint16
	err = util.Decode(bytes.NewBuffer(partialHeader[2:]), binary.BigEndian, &msgLen)
	if err != nil {
		return 0, fmt.Errorf("cannot decode message: %w", err)
	}
	return int(msgLen), nil
}

// getFieldLength returns string field length for data record
// (encoding reference: https://tools.ietf.org/html/rfc7011#appendix-A.5)
func getFieldLength(dataBuffer *bytes.Buffer) int {
	oneByte, _ := dataBuffer.ReadByte()
	if oneByte < 255 { // string length is less than 255
		return int(oneByte)
	}
	var lengthTwoBytes uint16
	util.Decode(dataBuffer, binary.BigEndian, &lengthTwoBytes)
	return int(lengthTwoBytes)
}
