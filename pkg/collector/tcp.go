package collector

import (
	"bytes"
	"fmt"
	"io"
	"k8s.io/klog"
	"net"
)

func (cp *CollectingProcess) startTCPServer(address net.Addr, maxBufferSize uint16) {
	listener, err := net.Listen("tcp", address.String())
	if err != nil {
		klog.Errorf("Cannot start collecting process on %s: %v", address.String(), err)
		return
	}

	klog.Infof("Start %s collecting process on %s", address.Network(), address.String())
	defer listener.Close()

	for {
		conn, err := listener.Accept()
		if err != nil {
			klog.Errorf("Cannot start collecting process on %s: %v", address.String(), err)
			return
		}
		go cp.handleTCPConnection(conn, maxBufferSize, address)
	}
}

func (cp *CollectingProcess) handleTCPConnection(conn net.Conn, maxBufferSize uint16, address net.Addr) {
	for {
		buff := make([]byte, maxBufferSize)
		size, err := conn.Read(buff)
		if err != nil {
			if err == io.EOF {
				klog.Infof("TCP Connection %s has been closed.", address.String())
			} else {
				klog.Errorf("Error in collecting process: %v", err)
			}
			return
		}
		klog.Infof("Receiving %d bytes from %s", size, address.String())
		message := make([]byte, size)
		copy(message, buff[0:size])
		for size > 0 {
			length, err := getMessageLength(bytes.NewBuffer(message))
			if err != nil {
				klog.Error(err)
				return
			}
			size = size - length
			// get the packet here
			packet, err := cp.DecodeMessage(bytes.NewBuffer(message[0:length]))
			if err != nil {
				klog.Error(err)
				return
			}
			klog.Info(packet)
			message = message[length:]
		}
	}
	conn.Close()
}

// get buffer length by decoding the header
func getMessageLength(msgBuffer *bytes.Buffer) (int, error) {
	packet := Packet{}
	flowSetHeader := FlowSetHeader{}
	err := decode(msgBuffer, &packet.Version, &packet.BufferLength, &packet.ExportTime, &packet.SeqNumber, &packet.ObsDomainID, &flowSetHeader)
	if err != nil {
		return 0, fmt.Errorf("Cannot decode message: %v", err)
	}
	return int(packet.BufferLength), nil
}