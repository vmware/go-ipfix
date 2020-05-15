package exporter

import "bytes"

const(
	maxTcpSocketMsgSize uint16 = 65536
)

type msgBuffer struct {
	buffer bytes.Buffer
	containsDataSet bool
}

func NewMsgBuffer() *msgBuffer {
	return &msgBuffer{
		buffer:   bytes.Buffer{},
		containsDataSet:  false,
	}
}
