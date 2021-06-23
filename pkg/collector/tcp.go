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
		var err error
		listener, err = net.Listen("tcp", cp.address)
		if err != nil {
			klog.Errorf("Cannot start collecting process on %s: %v", cp.address, err)
			return
		}
		cp.updateAddress(listener.Addr())
		klog.Infof("Start TCP collecting process on %s", cp.address)
	}
	defer listener.Close()
	go func(stopCh chan struct{}) {
		for {
			conn, err := listener.Accept()
			if err != nil {
				select {
				case <-stopCh:
					return
				default:
					klog.Errorf("Cannot start the connection on the collecting process at %s: %v", cp.address, err)
					return
				}
			}
			go cp.handleTCPClient(conn, stopCh)
		}
	}(cp.stopChan)
	<-cp.stopChan
}

func (cp *CollectingProcess) handleTCPClient(conn net.Conn, stopCh chan struct{}) {
	address := conn.RemoteAddr().String()
	client := cp.createClient()
	cp.addClient(address, client)
	defer conn.Close()
	buff := make([]byte, cp.maxBufferSize)
	for {
		select {
		case <-stopCh:
			cp.deleteClient(address)
			return
		default:
			size, err := conn.Read(buff)
			if err != nil {
				if err == io.EOF {
					klog.Infof("Connection from %s has been closed.", address)
				} else {
					klog.Errorf("Error in collecting process: %v", err)
				}
				cp.deleteClient(address)
				return
			}
			klog.V(2).Infof("Receiving %d bytes from %s", size, address)
			buffBytes := make([]byte, size)
			copy(buffBytes, buff[:size])
			for size > 0 {
				length, err := getMessageLength(bytes.NewBuffer(buffBytes))
				if err != nil {
					klog.Error(err)
					cp.deleteClient(address)
					return
				}
				if size < length {
					klog.Errorf("Message length %v is larger than size read from buffer %v", length, size)
					cp.deleteClient(address)
					return
				}
				size = size - length
				// get the message here
				message, err := cp.decodePacket(bytes.NewBuffer(buffBytes[0:length]), address)
				if err != nil {
					klog.Error(err)
					cp.deleteClient(address)
					return
				}
				klog.V(4).Infof("Processed message from exporter %v, number of records: %v, observation domain ID: %v",
					message.GetExportAddress(), message.GetSet().GetNumberOfRecords(), message.GetObsDomainID())
				buffBytes = buffBytes[length:]
			}
		}
	}
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
