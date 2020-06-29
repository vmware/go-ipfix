// Copyright 2020 go-ipfix Authors
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
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/vmware/go-ipfix/pkg/entities"
)

var uniqueTemplateID uint16 = 255

type templateValue struct{
	elementNames []string
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
	set             *entities.Set
	msg             *entities.MsgBuffer
	templatesMap    map[uint16]templateValue
}

func InitExportingProcess(collectorAddr net.Addr, obsID uint32) (*ExportingProcess, error) {
	conn, err := net.Dial(collectorAddr.Network(), collectorAddr.String())
	if err != nil {
		log.Printf("Cannot the create the connection to configured ExportingProcess %s. Error is %v", collectorAddr.String(), err)
		return nil, err
	}
	msgBuffer := entities.NewMsgBuffer()
	return &ExportingProcess{
		connToCollector: conn,
		obsDomainID:     obsID,
		seqNumber:       0,
		set:             entities.NewSet(msgBuffer.GetMsgBuffer()),
		msg:             msgBuffer,
		templatesMap:    make(map[uint16]templateValue),
	}, nil
}

func (ep *ExportingProcess) AddRecordAndSendMsg(recType entities.ContentType, rec entities.Record) (int, error) {
	if recType == entities.Template {
		ep.updateTemplate(rec.GetTemplateID(), rec.GetTemplateFields(), rec.GetMinDataRecordLen())
	} else if recType == entities.Data {
		err := ep.sanityCheck(rec)
		if err != nil {
			return 0, fmt.Errorf("error when doing sanity check:%v", err)
		}
	}
	recBytes := rec.GetBuffer().Bytes()

	msgBuffer := ep.msg.GetMsgBuffer()
	var bytesSent int
	// Check if message is exceeding the limit with new record
	if uint16(msgBuffer.Len()+len(recBytes)) > entities.MaxTcpSocketMsgSize {
		ep.set.FinishSet()
		b, err := ep.sendMsg()
		if err != nil {
			return b, err
		}
		bytesSent = bytesSent + b
	}
	if msgBuffer.Len() == 0 {
		err := ep.createNewMsg()
		if err != nil {
			return bytesSent, fmt.Errorf("error when creating message: %v", err)
		}
	}
	// Check set buffer length and type change to create new set in the message
	if ep.set.GetBuffLen() == 0 {
		ep.set.CreateNewSet(recType, uniqueTemplateID)
	} else if ep.set.GetSetType() != recType {
		ep.set.FinishSet()
		ep.set.CreateNewSet(recType, uniqueTemplateID)
	}
	// Write the record to the set
	err := ep.set.WriteRecordToSet(&recBytes)
	if err != nil {
		return bytesSent, fmt.Errorf("error when writing record to the set: %v", err)
	}
	if recType == entities.Data && !ep.msg.GetDataRecFlag() {
		ep.msg.SetDataRecFlag(true)
	}

	// Send the message right after attaching the record
	// TODO: Will add API to send multiple records at once
	ep.set.FinishSet()

	b, err := ep.sendMsg()
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
		log.Printf("Error in writing header to message buffer: %v", err)
		return err
	}
	return nil
}

func (ep *ExportingProcess) sendMsg() (int, error) {
	// Update length, time and sequence number
	msgBuffer := ep.msg.GetMsgBuffer()
	byteSlice := msgBuffer.Bytes()
	binary.BigEndian.PutUint16(byteSlice[2:4], uint16(msgBuffer.Len()))
	binary.BigEndian.PutUint32(byteSlice[4:8], uint32(time.Now().Unix()))
	binary.BigEndian.PutUint32(byteSlice[8:12], ep.seqNumber)
	if ep.msg.GetDataRecFlag() {
		ep.seqNumber = ep.seqNumber + 1
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

func (ep *ExportingProcess) CloseConnToCollector() error{
	err := ep.connToCollector.Close()
	return fmt.Errorf("error when closing connection to collector: %v", err)
}

func (ep *ExportingProcess) AddTemplate() uint16{
	uniqueTemplateID++
	ep.templatesMap[uniqueTemplateID] = templateValue{
		nil,
		0,
	}

	log.Printf("Template ID: %d", uniqueTemplateID)

	return uniqueTemplateID
}

func (ep *ExportingProcess) updateTemplate(id uint16, elementNames *[]string, minDataRecLen uint16) {
	ep.templatesMap[id] = templateValue{
		make([]string, len(*elementNames)),
		minDataRecLen,
	}
	for i, name := range *elementNames {
		ep.templatesMap[uniqueTemplateID].elementNames[i] = name
	}

	return
}


func (ep *ExportingProcess) deleteTemplate(id uint16) error{
	if _, exist := ep.templatesMap[id]; !exist {
		return fmt.Errorf("process: template %d does not exist in exporting process", id)
	}
	delete(ep.templatesMap, id)

	return nil
}

func (ep *ExportingProcess) sanityCheck(rec entities.Record) error{
	templateID := rec.GetTemplateID()
	if _, exist := ep.templatesMap[templateID]; !exist {
		return fmt.Errorf("process: templateID %d does not exist in exporting process", templateID)
	}
	if rec.GetFieldCount() != uint16(len(ep.templatesMap[templateID].elementNames)) {
		return fmt.Errorf("process: field count of data does not match templateID %d", templateID)
	}
	if rec.GetBuffer().Len() < int(ep.templatesMap[templateID].minDataRecLen) {
		return fmt.Errorf("process: Data Record does not pass the min required length (%d) check for template ID %d", ep.templatesMap[templateID].minDataRecLen, templateID)
	}
	return nil
}
