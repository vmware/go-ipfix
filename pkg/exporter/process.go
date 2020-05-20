package exporter

import (
	"encoding/binary"
	"log"
	"net"
	"time"

	"github.com/srikartati/go-ipfixlib/pkg/entities"
)

var _ ExportingProcess = new(exportingProcess)

type ExportingProcess interface {
	CreateNewMsg() error
	AddRecordToMsg(setType entities.SetOrRecordType, recBuffer *[]byte) error
	SendMsg()
}

// 1. Supports only one exportingProcess process per exporter.
// 2. Only one observation point per observation domain is supported,
//    so observation point ID not defined.
// 3. Supports only TCP session; SCTP and UDP is not supported.
// TODO:UDP needs to send MTU size packets as per RFC7011
type exportingProcess struct {
	connToCollector net.Conn
	obsDomainID     uint32
	seqNumber       uint32
	set             *entities.Set
	msg             *entities.MsgBuffer
}

// TODO: Add MTU parameter for UDP transport protocol
func InitExportingProcess(collectorAddr net.Addr, obsID uint32) *exportingProcess {
	conn, err := net.Dial(collectorAddr.Network(), collectorAddr.String())
	if err != nil {
		log.Fatalf("Cannot the create the connection to configured exportingProcess %s. Error is %v", collectorAddr.String(), err)
	}
	msgBuffer := entities.NewMsgBuffer()
	return &exportingProcess{
		connToCollector: conn,
		obsDomainID:     obsID,
		seqNumber:       0,
		set:             entities.NewSet(msgBuffer.GetMsgBuffer()),
		msg:             msgBuffer,
	}
}

func (ep *exportingProcess) CreateNewMsg() error {
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

func (ep *exportingProcess) AddRecordToMsg(recType entities.SetOrRecordType, recBuffer *[]byte) error {
	// Check if message is exceeding the limit with new record
	// Check for timeout too?
	msgBuffer := ep.msg.GetMsgBuffer()
	if uint16(msgBuffer.Len()+len(*recBuffer)) > entities.MaxTcpSocketMsgSize {
		ep.set.FinishSet()
		ep.SendMsg()
	}

	if msgBuffer.Len() == 0 {
		err := ep.CreateNewMsg()
		if err != nil {
			log.Fatalf("Cannot create new msg. Returned error: %v", err)
		}
		return err
	}
	// Check set buffer length and type change to create new set in the message
	if ep.set.GetBuffLen() == 0 {
		ep.set.CreateNewSet(recType)
	} else if ep.set.GetSetType() != recType {
		ep.set.FinishSet()
		ep.set.CreateNewSet(recType)
	}
	// Write the record to the set
	err := ep.set.WriteRecordToSet(recBuffer)
	if err != nil {
		log.Fatalf("Error in writing record to the current set: %v", err)
		return err
	}
	if recType == entities.Data && !ep.msg.GetDataRecFlag() {
		ep.msg.SetDataRecFlag(true)
	}

	return nil
}

func (ep *exportingProcess) SendMsg() {
	// Update length, time and sequence number
	msgBuffer := ep.msg.GetMsgBuffer()
	byteSlice := msgBuffer.Bytes()
	binary.BigEndian.PutUint16(byteSlice[2:4], uint16(msgBuffer.Len()))
	binary.BigEndian.PutUint32(byteSlice[4:8], uint32(time.Now().Unix()))
	binary.BigEndian.PutUint32(byteSlice[8:12], ep.seqNumber)
	if ep.msg.GetDataRecFlag() {
		ep.seqNumber = ep.seqNumber + 1
	}
	// Send msg on collector socket
	_, err := ep.connToCollector.Write(byteSlice)
	if err != nil {
		log.Fatalf("Error when sending message on collector connection: %v", err)
	}
	// Reset the message buffer
	msgBuffer.Reset()
	ep.msg.SetDataRecFlag(false)

}
