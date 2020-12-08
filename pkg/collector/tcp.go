package collector

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"sync"

	"k8s.io/klog"
)

func (cp *CollectingProcess) startTCPServer() {
	var listener net.Listener
	var err error
	if cp.isEncrypted { // use TLS
		config, err := cp.createServerConfig()
		if err != nil {
			klog.Error(err)
			return
		}
		listener, err = tls.Listen("tcp", cp.address.String(), config)
		if err != nil {
			klog.Errorf("Cannot start tls collecting process on %s: %v", cp.address.String(), err)
			return
		}
		cp.updateAddress(listener.Addr())
		klog.Infof("Start tls collecting process on %s", cp.address.String())
	} else {
		listener, err = net.Listen("tcp", cp.address.String())
		if err != nil {
			klog.Errorf("Cannot start collecting process on %s: %v", cp.address.String(), err)
			return
		}
		cp.updateAddress(listener.Addr())
		klog.Infof("Start %s collecting process on %s", cp.address.Network(), cp.address.String())
	}

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
	<-cp.stopChan
	// close all connections
	cp.closeAllClients()
	wg.Wait()
}

func (cp *CollectingProcess) handleTCPClient(conn net.Conn, wg *sync.WaitGroup) {
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
	<-client.errChan
	cp.deleteClient(address)
}

func (cp *CollectingProcess) createServerConfig() (*tls.Config, error) {
	cert, err := tls.X509KeyPair(cp.serverCert, cp.serverKey)
	if err != nil {
		return nil, err
	}
	if cp.caCert == nil {
		return &tls.Config{
			Certificates: []tls.Certificate{cert},
		}, nil
	}
	roots := x509.NewCertPool()
	ok := roots.AppendCertsFromPEM(cp.caCert)
	if !ok {
		return nil, fmt.Errorf("failed to parse root certificate")
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    roots,
	}, nil
}
