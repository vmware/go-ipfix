package collector

import (
	"bytes"
	"io"
	"net"
	"sync"

	"k8s.io/klog"
)

func (cp *collectingProcess) startTCPServer() {
	listener, err := net.Listen("tcp", cp.address.String())
	if err != nil {
		klog.Errorf("Cannot start collecting process on %s: %v", cp.address.String(), err)
		return
	}

	klog.Infof("Start %s collecting process on %s", cp.address.Network(), cp.address.String())
	var wg sync.WaitGroup
	go func() {
		defer listener.Close()
		for {
			conn, err := listener.Accept()
			if err != nil {
				klog.Errorf("Cannot start collecting process on %s: %v", cp.address.String(), err)
				return
			}
			wg.Add(1)
			go cp.handleTCPClient(conn, &wg)
		}
	}()
	if <-cp.stopChan {
		// close all connections
		for _, client := range cp.clients {
			client.errChan <- true
		}
		wg.Wait()
		return
	}
}

func (cp *collectingProcess) handleTCPClient(conn net.Conn, wg *sync.WaitGroup) {
	defer wg.Done()
	address := conn.RemoteAddr().String()
	client := cp.createClient()
	cp.addClient(address, client)
	go func() {
		defer conn.Close()
	out:
		for {
			buff := make([]byte, cp.maxBufferSize)
			size, err := conn.Read(buff)
			if err != nil {
				if err == io.EOF {
					klog.Infof("Connection from %s has been closed.", address)
				} else {
					klog.Errorf("Error in collecting process: %v", err)
				}
				break out
			}
			klog.V(2).Infof("Receiving %d bytes from %s", size, address)
			for size > 0 {
				length, err := getMessageLength(bytes.NewBuffer(buff))
				if err != nil {
					klog.Error(err)
					break out
				}
				size = size - length
				// get the message here
				message, err := cp.decodePacket(bytes.NewBuffer(buff[0:length]), address)
				if err != nil {
					klog.Error(err)
					break out
				}
				klog.V(4).Info(message)
				buff = buff[length:]
			}
		}
	}()
	if <-client.errChan {
		cp.deleteClient(address)
		return
	}
}
