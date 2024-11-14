package collector

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
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
		klog.Infof("Started TLS collecting process on %s", cp.netAddress)
	} else {
		var err error
		listener, err = net.Listen("tcp", cp.address)
		if err != nil {
			klog.Errorf("Cannot start collecting process on %s: %v", cp.address, err)
			return
		}
		cp.updateAddress(listener.Addr())
		klog.Infof("Start TCP collecting process on %s", cp.netAddress)
	}

	cp.wg.Add(1)
	go func(stopCh chan struct{}) {
		defer cp.wg.Done()
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
			cp.wg.Add(1)
			go func() {
				defer cp.wg.Done()
				cp.handleTCPClient(conn)
			}()
		}
	}(cp.stopChan)
	<-cp.stopChan
	listener.Close()
}

func (cp *CollectingProcess) handleTCPClient(conn net.Conn) {
	address := conn.RemoteAddr().String()
	// The channels stored in clientHandler are not needed for the TCP client, so we do not
	// initialize them.
	client := &clientHandler{}
	func() {
		cp.mutex.Lock()
		defer cp.mutex.Unlock()
		cp.clients[address] = client
	}()
	defer func() {
		cp.mutex.Lock()
		defer cp.mutex.Unlock()
		delete(cp.clients, address)
	}()
	defer conn.Close()
	reader := bufio.NewReader(conn)
	doneCh := make(chan struct{})
	cp.wg.Add(1)
	// We read from the connection in a separate goroutine, so we can stop immediately when
	// cp.StopChan is closed. An alternative would be to use a read deadline, and check
	// cp.StopChan at every iteration.
	go func() {
		defer cp.wg.Done()
		defer close(doneCh)
		for {
			length, err := getMessageLength(reader)
			if errors.Is(err, io.EOF) {
				klog.V(2).InfoS("Connection was closed by client")
				return
			}
			if err != nil {
				klog.ErrorS(err, "Error when retrieving message length")
				return
			}
			buff := make([]byte, length)
			_, err = io.ReadFull(reader, buff)
			if err != nil {
				klog.ErrorS(err, "Error when reading the message")
				return
			}
			message, err := cp.decodePacket(bytes.NewBuffer(buff), address)
			if err != nil {
				// This can be an invalid template record, or invalid data record.
				// We close the connection, which is the best way to let the client
				// (exporter) know that something is wrong.
				klog.ErrorS(err, "Error when decoding packet, closing connection")
				return
			}
			klog.V(4).InfoS("Processed message from exporter",
				"observationDomainID", message.GetObsDomainID(), "setType", message.GetSet().GetSetType(), "numRecords", message.GetSet().GetNumberOfRecords())
		}
	}()
	select {
	case <-cp.stopChan:
		break
	case <-doneCh:
		break
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
