package exporter

import (
	"encoding/binary"
	"log"
	"net"
	"time"

	"github.com/srikartati/go-ipfixlib/pkg/set"
)

var _ ExportingProcess = new(exportingProcess)

type ExportingProcess interface {
	CreateNewMsg() error
	AddRecordToMsg(setType set.SetOrRecordType)
	DoesMsgLenExceedLimit(extraLen uint16) bool
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
	set             *set.Set
	msg             *msgBuffer
}

// TODO: Add MTU parameter for UDP transport protocol
func InitExportingProcess(collectorAddr net.Addr, obsID uint32) *exportingProcess {
	conn, err := net.Dial(collectorAddr.Network(), collectorAddr.String())
	if err != nil {
		log.Fatalf("Cannot the create the connection to configured exportingProcess %s. Error is %v", collectorAddr.String(), err)
	}
	return &exportingProcess{
		connToCollector: conn,
		obsDomainID:     obsID,
		seqNumber:       0,
		set:			set.NewSet(),
		msg:            NewMsgBuffer(),
	}
}

func (ep *exportingProcess) CreateNewMsg() error {
	// Create the header and append it
	header := make([]byte, 16)
	// IPFIX version number is 10.
	// https://www.iana.org/assignments/ipfix/ipfix.xhtml#ipfix-version-numbers
	binary.BigEndian.PutUint16(header[0:2], 10)
	binary.BigEndian.PutUint32(header[12:], ep.obsDomainID)
    // Write the header to msg buffer
	_, err := ep.msg.buffer.Write(header)
	if err != nil {
		log.Fatalf("Error in writing header to message buffer: %v", err)
		return err
	}
	return nil
}

func (ep *exportingProcess) AddRecordToMsg(setType set.SetOrRecordType) {
	if ep.msg.buffer.Len() == 0 {
		err := ep.CreateNewMsg()
		if err != nil {
			log.Fatalf("Cannot create new msg. Returned error: %v", err)
		}
	}
	if setType == set.Data && !ep.msg.containsDataSet {
		ep.msg.containsDataSet = true
	}
	// Write the set to the msg buffer

}

// Useful to send message
func (ep *exportingProcess) DoesMsgLenExceedLimit(extraLen uint16) bool {
	//TODO: Change this to support UDP transport proto
	if (uint16(ep.msg.buffer.Len()) + extraLen) > maxTcpSocketMsgSize {
		return true
	}
	return false
}

func (ep *exportingProcess) SendMsg() {
	// Update length, time and sequence number
	byteSlice := ep.msg.buffer.Bytes()
	binary.BigEndian.PutUint16(byteSlice[2:4], uint16(ep.msg.buffer.Len()))
	binary.BigEndian.PutUint32(byteSlice[4:8], uint32(time.Now().Unix()))
	binary.BigEndian.PutUint32(byteSlice[8:12], ep.seqNumber)
	if ep.msg.containsDataSet {
		ep.seqNumber = ep.seqNumber + 1
	}
	// Send msg on collector socket
	_, err := ep.connToCollector.Write(byteSlice)
	if err != nil {
		log.Fatalf("Error when sending message on collector connection: %v", err)
	}
	// Reset the message buffer
	ep.msg.buffer.Reset()
	ep.msg.containsDataSet = false
}

