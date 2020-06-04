package exporter

import (
	"net"
	"testing"

	"github.com/srikartati/go-ipfixlib/pkg/entities"
	"github.com/srikartati/go-ipfixlib/pkg/registry"
	"github.com/stretchr/testify/assert"
)

func TestExportingProcess_SendingTemplateRecordToLocalTCPServer(t *testing.T) {
	reg := registry.NewIanaRegistry()
	reg.LoadRegistry()

	// Create template record with two fields
	tempRec := entities.NewTemplateRecord(2)
	tempRec.PrepareRecord()
	element, err := reg.GetInfoElement("sourceIPv4Address")
	if err != nil {
		t.Errorf("Did not find the element with name sourceIPv4Address")
	}
	tempRec.AddInfoElement(element, nil)
	element, err = reg.GetInfoElement("destinationIPv4Address")
	if err != nil {
		t.Errorf("Did not find the element with name destinationIPv4Address")
	}
	tempRec.AddInfoElement(element, nil)
	tempRecBuff := tempRec.GetBuffer()
	tempRecBytes := tempRecBuff.Bytes()

	// Create local server for testing
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatalf("Got error when creating a local server: %v", err)
	}
	t.Log("Created local server on random available port for testing")

	buffCh := make(chan []byte)
	// Create go routine for local server
	// TODO: Move this in to different function with byte size as arg
	go func() {
		defer listener.Close()
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		t.Log("Accept the connection from exporter")
		buff := make([]byte, 32)
		_, err = conn.Read(buff)
		if err != nil {
			t.Fatal(err)
		}
		// Compare only template record part. Remove message header and set header.
		buffCh <- buff[20:]
		return
	}()

	// Create exporter using local server info
	exporter, err := InitExportingProcess(listener.Addr(), 1)
	if err != nil {
		t.Fatalf("Got error when connecting to local server %s: %v", listener.Addr().String(), err)
	}
	t.Logf("Created exporter connecting to local server with address: %s", listener.Addr().String())
	bytesSent, err := exporter.AddRecordAndSendMsg(entities.Template, &tempRecBytes)
	if err != nil {
		t.Fatalf("Got error when sending record: %v", err)
	}
	// 32 is the size of the IPFIX message including all headers
	assert.Equal(t, 32, bytesSent)
	assert.Equal(t, tempRecBytes, <-buffCh)
	assert.Equal(t, uint32(0), exporter.seqNumber)
	exporter.CloseConnToCollector()
}

func TestExportingProcess_SendingTemplateRecordToLocalUDPServer(t *testing.T) {
	reg := registry.NewIanaRegistry()
	reg.LoadRegistry()

	// Create template record with two fields
	tempRec := entities.NewTemplateRecord(2)
	tempRec.PrepareRecord()
	element, err := reg.GetInfoElement("sourceIPv4Address")
	if err != nil {
		t.Errorf("Did not find the element with name sourceIPv4Address")
	}
	tempRec.AddInfoElement(&element, nil)
	element, err = reg.GetInfoElement("destinationIPv4Address")
	if err != nil {
		t.Errorf("Did not find the element with name destinationIPv4Address")
	}
	tempRec.AddInfoElement(&element, nil)
	tempRecBuff := tempRec.GetBuffer()
	tempRecBytes := tempRecBuff.Bytes()

	// Create local server for testing
	udpAddr, err := net.ResolveUDPAddr("udp", ":0")
	if err != nil {
		t.Fatalf("Got error when resolving UDP address: %v", err)
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		t.Fatalf("Got error when creating a local server: %v", err)
	}
	t.Log("Created local server on random available port for testing")

	buffCh := make(chan []byte)
	// Create go routine for local server
	// TODO: Move this in to different function with byte size as arg
	go func() {
		defer conn.Close()
		buff := make([]byte, 32)
		_, err = conn.Read(buff)
		if err != nil {
			t.Fatal(err)
		}
		// Compare only template record part. Remove message header and set header.
		buffCh <- buff[20:]
		return
	}()

	// Create exporter using local server info
	exporter, err := InitExportingProcess(conn.LocalAddr(), 1)
	if err != nil {
		t.Fatalf("Got error when connecting to local server %s: %v", conn.LocalAddr().String(), err)
	}
	t.Logf("Created exporter connecting to local server with address: %s", conn.LocalAddr().String())
	bytesSent, err := exporter.AddRecordAndSendMsg(entities.Template, &tempRecBytes)
	if err != nil {
		t.Fatalf("Got error when sending record: %v", err)
	}
	// 32 is the size of the IPFIX message including all headers
	assert.Equal(t, 32, bytesSent)
	assert.Equal(t, tempRecBytes, <-buffCh)
	assert.Equal(t, uint32(0), exporter.seqNumber)
	exporter.CloseConnToCollector()
}

func TestExportingProcess_SendingDataRecordToLocalTCPServer(t *testing.T) {
	reg := registry.NewIanaRegistry()
	reg.LoadRegistry()

	// Create template record with two fields
	dataRec := entities.NewDataRecord()
	dataRec.PrepareRecord()
	element, err := reg.GetInfoElement("sourceIPv4Address")
	if err != nil {
		t.Errorf("Did not find the element with name sourceIPv4Address")
	}
	dataRec.AddInfoElement(element, net.ParseIP("1.2.3.4"))

	element, err = reg.GetInfoElement("destinationIPv4Address")
	if err != nil {
		t.Errorf("Did not find the element with name destinationIPv4Address")
	}
	dataRec.AddInfoElement(element, net.ParseIP("5.6.7.8"))
	dataRecBuff := dataRec.GetBuffer()
	dataRecBytes := dataRecBuff.Bytes()

	// Create local server for testing
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatalf("Got error when creating a local server: %v", err)
	}
	t.Log("Created local server on random available port for testing")

	buffCh := make(chan []byte)
	// Create go routine for local server
	// TODO: Move this in to different function with byte size as arg
	go func() {
		defer listener.Close()
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		t.Log("Accept the connection from exporter")
		buff := make([]byte, 28)
		_, err = conn.Read(buff)
		if err != nil {
			t.Fatal(err)
		}
		// Compare only data record part. Remove message header and set header.
		// TODO: Verify message header and set header through hardcoded byte values
		buffCh <- buff[20:]
		return
	}()

	// Create exporter using local server info
	exporter, err := InitExportingProcess(listener.Addr(), 1)
	if err != nil {
		t.Fatalf("Got error when connecting to local server %s: %v", listener.Addr().String(), err)
	}
	t.Logf("Created exporter connecting to local server with address: %s", listener.Addr().String())
	bytesSent, err := exporter.AddRecordAndSendMsg(entities.Data, &dataRecBytes)
	if err != nil {
		t.Fatalf("Got error when sending record: %v", err)
	}
	// 28 is the size of the IPFIX message including all headers (20 bytes)
	assert.Equal(t, 28, bytesSent)
	assert.Equal(t, dataRecBytes, <-buffCh)
	assert.Equal(t, uint32(1), exporter.seqNumber)
	exporter.CloseConnToCollector()
}

func TestExportingProcess_SendingDataRecordToLocalUDPServer(t *testing.T) {
	reg := registry.NewIanaRegistry()
	reg.LoadRegistry()

	// Create template record with two fields
	dataRec := entities.NewDataRecord()
	dataRec.PrepareRecord()
	element, err := reg.GetInfoElement("sourceIPv4Address")
	if err != nil {
		t.Errorf("Did not find the element with name sourceIPv4Address")
	}
	dataRec.AddInfoElement(&element, net.ParseIP("1.2.3.4"))

	element, err = reg.GetInfoElement("destinationIPv4Address")
	if err != nil {
		t.Errorf("Did not find the element with name destinationIPv4Address")
	}
	dataRec.AddInfoElement(&element, net.ParseIP("5.6.7.8"))
	dataRecBuff := dataRec.GetBuffer()
	dataRecBytes := dataRecBuff.Bytes()

	// Create local server for testing
	udpAddr, err := net.ResolveUDPAddr("udp", ":0")
	if err != nil {
		t.Fatalf("Got error when resolving UDP address: %v", err)
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	t.Log("Created local server on random available port for testing")

	buffCh := make(chan []byte)
	// Create go routine for local server
	// TODO: Move this in to different function with byte size as arg
	go func() {
		defer conn.Close()
		buff := make([]byte, 28)
		_, err = conn.Read(buff)
		if err != nil {
			t.Fatal(err)
		}
		// Compare only data record part. Remove message header and set header.
		// TODO: Verify message header and set header through hardcoded byte values
		buffCh <- buff[20:]
		return
	}()

	// Create exporter using local server info
	exporter, err := InitExportingProcess(conn.LocalAddr(), 1)
	if err != nil {
		t.Fatalf("Got error when connecting to local server %s: %v", conn.LocalAddr().String(), err)
	}
	t.Logf("Created exporter connecting to local server with address: %s", conn.LocalAddr().String())
	bytesSent, err := exporter.AddRecordAndSendMsg(entities.Data, &dataRecBytes)
	if err != nil {
		t.Fatalf("Got error when sending record: %v", err)
	}
	// 28 is the size of the IPFIX message including all headers (20 bytes)
	assert.Equal(t, 28, bytesSent)
	assert.Equal(t, dataRecBytes, <-buffCh)
	assert.Equal(t, uint32(1), exporter.seqNumber)
	exporter.CloseConnToCollector()
}
