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

package exporter

import (
	"fmt"
	"net"
	"sync"
	"time"

	"k8s.io/klog"

	"github.com/vmware/go-ipfix/pkg/entities"
)

const startTemplateID uint16 = 255

type templateValue struct {
	elements      []*entities.InfoElement
	minDataRecLen uint16
}

// 1. Tested one exportingProcess process per exporter. Can support multiple collector scenario by
//    creating different instances of exporting process. Need to be tested
// 2. Only one observation point per observation domain is supported,
//    so observation point ID not defined.
// 3. Supports only TCP and UDP; one session at a time. SCTP is not supported.
// TODO:UDP needs to send MTU size packets as per RFC7011
type ExportingProcess struct {
	connToCollector net.Conn
	obsDomainID     uint32
	seqNumber       uint32
	templateID      uint16
	message         *entities.Message
	templatesMap    map[uint16]templateValue
	templateRefCh   chan struct{}
	mutex           sync.Mutex
}

// InitExportingProcess takes in collector address(net.Addr format), obsID(observation ID) and tempRefTimeout
// (template refresh timeout). tempRefTimeout is applicable only for collectors listening over UDP; unit is seconds. For TCP, you can
// pass any value. For UDP, if 0 is passed, consider 1800s as default.
// TODO: Get obsID, tempRefTimeout as args which can be of dynamic size supporting both TCP and UDP.
func InitExportingProcess(collectorAddr net.Addr, obsID uint32, tempRefTimeout uint32) (*ExportingProcess, error) {
	conn, err := net.Dial(collectorAddr.Network(), collectorAddr.String())
	if err != nil {
		klog.Errorf("Cannot the create the connection to configured ExportingProcess %s: %v", collectorAddr.String(), err)
		return nil, err
	}
	message := entities.NewMessage(false)

	expProc := &ExportingProcess{
		connToCollector: conn,
		obsDomainID:     obsID,
		seqNumber:       0,
		templateID:      startTemplateID,
		message:         message,
		templatesMap:    make(map[uint16]templateValue),
		templateRefCh:   make(chan struct{}),
	}

	// Template refresh logic is only for UDP transport.
	if collectorAddr.Network() == "udp" {
		if tempRefTimeout == 0 {
			// Default value
			tempRefTimeout = entities.TemplateRefreshTimeOut
		}
		go func() {
			ticker := time.NewTicker(time.Duration(tempRefTimeout) * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-expProc.templateRefCh:
					break
				case <-ticker.C:
					err := expProc.sendRefreshedTemplates()
					if err != nil {
						// Other option is sending messages through channel to library consumers
						klog.Errorf("Error when sending refreshed templates: %v. Closing the connection to IPFIX controller", err)
						expProc.CloseConnToCollector()
					}
				}
			}
		}()
	}

	return expProc, nil
}

func (ep *ExportingProcess) AddSetAndSendMsg(setType entities.ContentType, set entities.Set) (int, error) {
	// Iterate over all records in the set.
	for _, record := range set.GetRecords() {
		if setType == entities.Template {
			ep.updateTemplate(record.GetTemplateID(), record.GetOrderedElementList(), record.GetMinDataRecordLen())
		} else if setType == entities.Data {
			err := ep.dataRecSanityCheck(record)
			if err != nil {
				return 0, fmt.Errorf("AddSetAndSendMsg: error when doing sanity check:%v", err)
			}
		}
	}

	bytesSent := 0
	// Check if message is exceeding the limit with new set
	// TODO: Change the limit for UDP transport. This is only valid for TCP transport.
	if uint16(ep.message.GetMsgBufferLen()+int(set.GetBuffLen())) > entities.MaxTcpSocketMsgSize {
		return bytesSent, fmt.Errorf("set size exceeds max socket size")
	}
	if ep.message.GetMsgBufferLen() == 0 {
		// Create the header and write to message
		_, err := ep.message.CreateHeader()
		if err != nil {
			return bytesSent, fmt.Errorf("error when creating header: %v", err)
		}
		// IPFIX version number is 10.
		// https://www.iana.org/assignments/ipfix/ipfix.xhtml#ipfix-version-numbers
		ep.message.SetVersion(10)
		ep.message.SetObsDomainID(ep.obsDomainID)
	}

	// Update the length in set header before sending.
	set.UpdateLenInHeader()
	_, err := ep.message.WriteToMsgBuffer(set.GetBuffer().Bytes())
	if err != nil {
		return 0, err
	}
	b, err := ep.sendMsg(set)
	if err != nil {
		return bytesSent, err
	}
	bytesSent = bytesSent + b

	return bytesSent, nil
}

func (ep *ExportingProcess) CloseConnToCollector() {
	if !isChanClosed(ep.templateRefCh) {
		close(ep.templateRefCh) // Close template refresh channel
	}

	err := ep.connToCollector.Close()
	// Just log the error that happened when closing the connection. Not returning error as we do not expect library
	// consumers to exit their programs with this error.
	if err != nil {
		klog.Errorf("Error when closing connection to collector: %v", err)
	}
}

// NewTemplateID is called to get ID when creating new template record.
func (ep *ExportingProcess) NewTemplateID() uint16 {
	ep.templateID++
	return ep.templateID
}

func (ep *ExportingProcess) sendMsg(set entities.Set) (int, error) {
	// Update length, time and sequence number in the message header.
	ep.message.SetMessageLen(uint16(ep.message.GetMsgBufferLen()))
	ep.message.SetExportTime(uint32(time.Now().Unix()))
	if set.GetSetType() == entities.Data {
		ep.seqNumber = ep.seqNumber + set.GetNumberOfRecords()
	}
	ep.message.SetSequenceNum(ep.seqNumber)

	// Send the message on the exporter connection.
	bytesSent, err := ep.connToCollector.Write(ep.message.GetMsgBuffer().Bytes())
	if err != nil {
		ep.message.ResetMsgBuffer()
		return bytesSent, fmt.Errorf("error when sending message on the connection: %v", err)
	} else if bytesSent != int(ep.message.GetMessageLen()) {
		ep.message.ResetMsgBuffer()
		return bytesSent, fmt.Errorf("could not send the complete message on the connection")
	}
	// Reset the message buffer
	ep.message.ResetMsgBuffer()
	return bytesSent, nil
}

func (ep *ExportingProcess) updateTemplate(id uint16, elements []*entities.InfoElementWithValue, minDataRecLen uint16) {
	ep.mutex.Lock()
	defer ep.mutex.Unlock()

	if _, exist := ep.templatesMap[id]; exist {
		return
	}
	ep.templatesMap[id] = templateValue{
		make([]*entities.InfoElement, len(elements)),
		minDataRecLen,
	}
	for i, elem := range elements {
		ep.templatesMap[id].elements[i] = elem.Element
	}
	return
}

func (ep *ExportingProcess) deleteTemplate(id uint16) error {
	ep.mutex.Lock()
	defer ep.mutex.Unlock()

	if _, exist := ep.templatesMap[id]; !exist {
		return fmt.Errorf("process: template %d does not exist in exporting process", id)
	}
	delete(ep.templatesMap, id)
	return nil
}

func (ep *ExportingProcess) sendRefreshedTemplates() error {
	// Send refreshed template for every template in template map
	templateSets := make([]entities.Set, 0)
	ep.mutex.Lock()
	for templateID, tempValue := range ep.templatesMap {
		tempSet := entities.NewSet(entities.Template, templateID, false)
		elements := make([]*entities.InfoElementWithValue, 0)
		for _, element := range tempValue.elements {
			ie := entities.NewInfoElementWithValue(element, nil)
			elements = append(elements, ie)
		}
		tempSet.AddRecord(elements, templateID)
		templateSets = append(templateSets, tempSet)
	}
	ep.mutex.Unlock()

	for _, templateSet := range templateSets {
		if _, err := ep.AddSetAndSendMsg(entities.Template, templateSet); err != nil {
			return err
		}
	}
	return nil
}

func (ep *ExportingProcess) dataRecSanityCheck(rec entities.Record) error {
	templateID := rec.GetTemplateID()

	ep.mutex.Lock()
	defer ep.mutex.Unlock()

	if _, exist := ep.templatesMap[templateID]; !exist {
		return fmt.Errorf("process: templateID %d does not exist in exporting process", templateID)
	}
	if rec.GetFieldCount() != uint16(len(ep.templatesMap[templateID].elements)) {
		return fmt.Errorf("process: field count of data does not match templateID %d", templateID)
	}
	if rec.GetBuffer().Len() < int(ep.templatesMap[templateID].minDataRecLen) {
		return fmt.Errorf("process: Data Record does not pass the min required length (%d) check for template ID %d", ep.templatesMap[templateID].minDataRecLen, templateID)
	}
	return nil
}

func isChanClosed(ch <-chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
	}
	return false
}
