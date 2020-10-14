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
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
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
// 3. Supports only TCP session; SCTP and UDP is not supported.
// TODO:UDP needs to send MTU size packets as per RFC7011
// TODO: Add function to send multiple records simultaneously
type ExportingProcess struct {
	connToCollector net.Conn
	obsDomainID     uint32
	seqNumber       uint32
	templateID      uint16
	set             entities.Set
	msg             *entities.MsgBuffer
	templatesMap    map[uint16]templateValue
	templateRefCh   chan struct{}
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
	msgBuffer := entities.NewMsgBuffer()

	expProc := &ExportingProcess{
		connToCollector: conn,
		obsDomainID:     obsID,
		seqNumber:       0,
		templateID:      startTemplateID,
		set:             entities.NewSet(msgBuffer.GetMsgBuffer()),
		msg:             msgBuffer,
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
	recBytes := make([]byte, 0)
	for _, record := range set.GetRecords() {
		if setType == entities.Template {
			ep.updateTemplate(record.GetTemplateID(), record.GetInfoElements(), record.GetMinDataRecordLen())
		} else if setType == entities.Data {
			err := ep.dataRecSanityCheck(record)
			if err != nil {
				return 0, fmt.Errorf("AddRecordAndSendMsg: error when doing sanity check:%v", err)
			}
		}
		for _, byte := range record.GetBuffer().Bytes() {
			recBytes = append(recBytes, byte)
		}
	}

	msgBuffer := ep.msg.GetMsgBuffer()
	var bytesSent int
	// Check if message is exceeding the limit with new record
	if uint16(msgBuffer.Len()+len(recBytes)) > entities.MaxTcpSocketMsgSize {
		ep.set.FinishSet()
		b, err := ep.sendMsg(set.GetNumberOfRecords())
		if err != nil {
			return b, err
		}
		bytesSent = bytesSent + b
	}
	if msgBuffer.Len() == 0 {
		err := ep.createNewMsg()
		if err != nil {
			return bytesSent, fmt.Errorf("AddRecordAndSendMsg: error when creating message: %v", err)
		}
	}
	// Check set buffer length and type change to create new set in the message
	if ep.set.GetBuffLen() == 0 {
		ep.set.CreateNewSet(setType, set.GetRecords()[0].GetTemplateID())
	} else if ep.set.GetSetType() != setType {
		ep.set.FinishSet()
		ep.set.CreateNewSet(setType, set.GetRecords()[0].GetTemplateID())
	}
	// Write the record to the set
	err := ep.set.WriteRecordToSet(&recBytes)
	if err != nil {
		return bytesSent, fmt.Errorf("AddRecordAndSendMsg: %v", err)
	}
	if setType == entities.Data && !ep.msg.GetDataRecFlag() {
		ep.msg.SetDataRecFlag(true)
	}

	// Send the message right after attaching the record
	ep.set.FinishSet()

	b, err := ep.sendMsg(set.GetNumberOfRecords())
	if err != nil {
		return bytesSent, err
	}
	bytesSent = bytesSent + b

	return bytesSent, nil
}

func (ep *ExportingProcess) createNewMsg() error {
	// Create the header and write to message
	header := make([]byte, 16)
	// IPFIX version number is 10.
	// https://www.iana.org/assignments/ipfix/ipfix.xhtml#ipfix-version-numbers
	binary.BigEndian.PutUint16(header[0:2], 10)
	binary.BigEndian.PutUint32(header[12:], ep.obsDomainID)
	// Write the header to msg buffer
	msgBuffer := ep.msg.GetMsgBuffer()
	_, err := msgBuffer.Write(header)
	if err != nil {
		return fmt.Errorf("createNewMsg: %v", err)
	}
	return nil
}

func (ep *ExportingProcess) sendMsg(numOfRecords uint32) (int, error) {
	// Update length, time and sequence number
	msgBuffer := ep.msg.GetMsgBuffer()
	byteSlice := msgBuffer.Bytes()
	binary.BigEndian.PutUint16(byteSlice[2:4], uint16(msgBuffer.Len()))
	binary.BigEndian.PutUint32(byteSlice[4:8], uint32(time.Now().Unix()))
	binary.BigEndian.PutUint32(byteSlice[8:12], ep.seqNumber)
	if ep.msg.GetDataRecFlag() {
		ep.seqNumber = ep.seqNumber + numOfRecords
	}
	// Send msg on the connection
	bytesSent, err := ep.connToCollector.Write(byteSlice)
	if err != nil {
		// Reset the message buffer and return error
		msgBuffer.Reset()
		ep.msg.SetDataRecFlag(false)
		return bytesSent, fmt.Errorf("error when sending message on controller connection: %v", err)
	} else if bytesSent == 0 && len(byteSlice) != 0 {
		return 0, fmt.Errorf("sent 0 bytes; message is of length: %d", len(byteSlice))
	}
	// Reset the message buffer
	msgBuffer.Reset()
	ep.msg.SetDataRecFlag(false)

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

func (ep *ExportingProcess) updateTemplate(id uint16, elements []*entities.InfoElementValue, minDataRecLen uint16) {
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
	if _, exist := ep.templatesMap[id]; !exist {
		return fmt.Errorf("process: template %d does not exist in exporting process", id)
	}
	delete(ep.templatesMap, id)
	return nil
}

func (ep *ExportingProcess) sendRefreshedTemplates() error {
	// Send refreshed template for every template in template map
	for templateID, tempValue := range ep.templatesMap {
		tempSet := entities.NewSet(&bytes.Buffer{})
		tempSet.CreateNewSet(entities.Template, templateID)
		elements := make([]*entities.InfoElementValue, 0)
		for _, element := range tempValue.elements {
			ie := entities.NewInfoElementValue(element, nil)
			elements = append(elements, ie)
		}
		tempSet.AddRecord(elements, templateID, false)
		if _, err := ep.AddSetAndSendMsg(entities.Template, tempSet); err != nil {
			return err
		}
	}
	return nil
}

func (ep *ExportingProcess) dataRecSanityCheck(rec entities.Record) error {
	templateID := rec.GetTemplateID()
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
