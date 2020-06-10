package exporter

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/srikartati/go-ipfixlib/pkg/entities"
)

//go:generate mockgen -destination=testing/mock_process.go -package=testing github.com/srikartati/go-ipfixlib/pkg/exporter ExportingProcess

var uniqueTemplateID uint16 = 255

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
	templates       map[uint16][]string
}

func InitExportingProcess(collectorAddr net.Addr, obsID uint32) (*ExportingProcess, error) {
	conn, err := net.Dial(collectorAddr.Network(), collectorAddr.String())
	if err != nil {
		log.Fatalf("Cannot the create the connection to configured ExportingProcess %s. Error is %v", collectorAddr.String(), err)
		return nil, err
	}
	msgBuffer := entities.NewMsgBuffer()
	return &ExportingProcess{
		connToCollector: conn,
		obsDomainID:     obsID,
		seqNumber:       0,
		set:             entities.NewSet(msgBuffer.GetMsgBuffer()),
		msg:             msgBuffer,
		templates:       make(map[uint16][]string),
	}, nil
}

func (ep *ExportingProcess) AddRecordAndSendMsg(recType entities.ContentType, rec entities.Record) (int, error) {
	if recType == entities.Template {
		ep.addTemplate(rec.GetTemplateFields())
	} else if recType == entities.Data {
		ep.sanityCheck(rec)
	}
	recBytes := rec.GetBuffer().Bytes()

	msgBuffer := ep.msg.GetMsgBuffer()
	var bytesSent int
	// Check if message is exceeding the limit with new record
	if uint16(msgBuffer.Len()+len(recBytes)) > entities.MaxTcpSocketMsgSize {
		ep.set.FinishSet()
		b, err := ep.sendMsg()
		if err != nil {
			log.Fatalf("Sending msg as it exceeded max msg size. Returned error: %v", err)
		}
		bytesSent = bytesSent + b
	}
	if msgBuffer.Len() == 0 {
		err := ep.createNewMsg()
		if err != nil {
			log.Fatalf("Cannot create new msg. Returned error: %v", err)
			return bytesSent, err
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
		log.Fatalf("Error in writing record to the current set: %v", err)
		return bytesSent, err
	}
	if recType == entities.Data && !ep.msg.GetDataRecFlag() {
		ep.msg.SetDataRecFlag(true)
	}

	// Send the message right after attaching the record
	// TODO: Will add API to send multiple records at once
	ep.set.FinishSet()

	b, err := ep.sendMsg()
	if err != nil {
		log.Fatalf("Sending msg as it exceeded max msg size. Returned error: %v", err)
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
		log.Fatalf("Error in writing header to message buffer: %v", err)
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
		log.Fatalf("Error when sending message on collector connection: %v", err)
		return bytesSent, err
	} else if bytesSent == 0 && len(byteSlice) != 0 {
		return 0, fmt.Errorf("sent 0 bytes; message is of length: %d", len(byteSlice))
	}
	// Reset the message buffer
	msgBuffer.Reset()
	ep.msg.SetDataRecFlag(false)

	return bytesSent, nil
}

func (ep *ExportingProcess) CloseConnToCollector() {
	ep.connToCollector.Close()
	return
}

// Leaving this for now to get better ideas on how to use mocks for testing in this scenario.
func funcToTestAddRecordMsg(ep ExportingProcess, recType entities.ContentType, rec entities.Record) (int, error) {
	return ep.AddRecordAndSendMsg(recType, rec)
}

func (ep *ExportingProcess) addTemplate(names *[]string) {
	uniqueTemplateID++
	templates := ep.templates
	templates[uniqueTemplateID] = *names
	log.Printf("Template ID: %d", uniqueTemplateID)
}

func (ep *ExportingProcess) deleteTemplate(id uint16) {
	if _, exist := ep.templates[id]; !exist {
		log.Fatalf("process: template %d does not exist in exporting process", id)
	}
	delete(ep.templates, id)
}

func (ep *ExportingProcess) sanityCheck(rec entities.Record) {
	template := rec.GetTemplateID()
	if _, exist := ep.templates[template]; !exist {
		log.Fatalf("process: template %d does not exist in exporting process", template)
	}
	templateFieldCount := len(ep.templates[template])
	if rec.GetFieldCount() != uint16(templateFieldCount) {
		log.Fatalf("process: field count of data does not match template %d", template)
	}
}
