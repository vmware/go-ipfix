package collector

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"

	"k8s.io/klog/v2"
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
		listener, err = tls.Listen("tcp", cp.address, config)
		if err != nil {
			klog.Errorf("Cannot start tls collecting process on %s: %v", cp.address, err)
			return
		}
		cp.updateAddress(listener.Addr())
		klog.Infof("Started TLS collecting process on %s", cp.address)
	} else {
		listener, err = net.Listen("tcp", cp.address)
		if err != nil {
			klog.Errorf("Cannot start collecting process on %s: %v", cp.address, err)
			return
		}
		cp.updateAddress(listener.Addr())
		klog.Infof("Start TCP collecting process on %s", cp.address)
	}

	go func() {
		defer listener.Close()
		for {
			conn, err := listener.Accept()
			if err != nil {
				klog.Errorf("Cannot start collecting process on %s: %v", cp.address, err)
				return
			}
			go cp.handleTCPClient(conn)
		}
	}()
	<-cp.stopChan
	// close all connections
	cp.closeAllClients()
}

func (cp *CollectingProcess) handleTCPClient(conn net.Conn) {
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
				client.errChan <- true
				break out
			}
			klog.V(2).Infof("Receiving %d bytes from %s", size, address)
			for size > 0 {
				length, err := getMessageLength(bytes.NewBuffer(buff))
				if err != nil {
					klog.Error(err)
					client.errChan <- true
					break out
				}
				if size < length {
					klog.Errorf("Message length %v is larger than size read from buffer %v", length, size)
					break out
				}
				size = size - length
				// get the message here
				message, err := cp.decodePacket(bytes.NewBuffer(buff[0:length]), address)
				if err != nil {
					klog.Error(err)
					client.errChan <- true
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
			MinVersion:   tls.VersionTLS12,
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
		MinVersion:   tls.VersionTLS12,
	}, nil
}
