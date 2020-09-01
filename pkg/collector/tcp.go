package collector

import (
	"bytes"
	"io"
	"net"

	"k8s.io/klog/v2"
)

// number of connections
var connCount = 0

func (cp *collectingProcess) startTCPServer() {
	listener, err := net.Listen("tcp", cp.address.String())
	if err != nil {
		klog.Errorf("Cannot start collecting process on %s: %v", cp.address.String(), err)
		return
	}

	klog.Infof("Start %s collecting process on %s", cp.address.Network(), cp.address.String())
	go func() {
		defer listener.Close()
		for {
			conn, err := listener.Accept()
			if err != nil {
				klog.Errorf("Cannot start collecting process on %s: %v", cp.address.String(), err)
				return
			}
			go cp.handleConnection(conn)
		}
	}()
	select {
	case <-cp.stopChan:
		return
	}
}

func (cp *collectingProcess) handleConnection(conn net.Conn) {
	connCount++
	defer conn.Close()
out:
	for {
		buff := make([]byte, cp.maxBufferSize)
		size, err := conn.Read(buff)
		if err != nil {
			if err == io.EOF {
				klog.Infof("Connection %s has been closed.", cp.address.String())
			} else {
				klog.Errorf("Error in collecting process: %v", err)
			}
			break out
		}
		klog.Infof("Receiving %d bytes from %s", size, cp.address.String())
		packet := make([]byte, size)
		copy(packet, buff[0:size])
		for size > 0 {
			length, err := getMessageLength(bytes.NewBuffer(packet))
			if err != nil {
				klog.Error(err)
				break out
			}
			size = size - length
			// get the message here
			message, err := cp.decodePacket(bytes.NewBuffer(packet[0:length]))
			if err != nil {
				klog.Error(err)
				break out
			}
			klog.Info(message)
			packet = packet[length:]
		}
	}
	connCount--
}
