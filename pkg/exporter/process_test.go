package exporter

import (
	"net"
	"testing"

	//"github.com/golang/mock/gomock"
	"github.com/srikartati/go-ipfixlib/pkg/entities"
	//exptest "github.com/srikartati/go-ipfixlib/pkg/exporter/testing"
	//testEntities "github.com/srikartati/go-ipfixlib/pkg/entities/testing"
	"github.com/srikartati/go-ipfixlib/pkg/registry"
	"github.com/stretchr/testify/assert"
)

// Here testing with mocks doesn't seem to be useful. Want to remove it.
// TODO: Leaving to get comments to get ideas on making testing with mocks useful.
/*func TestExportingProcess_AddRecordToMsg(t *testing.T) {
	reg := registry.NewIanaRegistry()
	reg.LoadRegistry()

	ctrl := gomock.NewController(t)

	defer ctrl.Finish()

	mockExporter := exptest.NewMockExportingProcess(ctrl)

	// Create mock template record with two fields
	mockRecord := testEntities.NewMockRecord(ctrl)

	mockRecord.EXPECT().PrepareRecord().Return(uint16(4), nil)
	if _, err := mockRecord.PrepareRecord(); err != nil {
		t.Errorf("Error when preparing records: %v", err)
	}

	element, err := reg.GetInfoElement("sourceIPv4Address")
	if err != nil {
		t.Errorf("Did not find the elements with name sourceIPv4Address")
	}
	mockRecord.EXPECT().AddInfoElement(element, nil).Return(nil)
	if err := mockRecord.AddInfoElement(element, nil); err != nil {
		t.Errorf("Error when adding info element %s: %v", element.Name, err)
	}

	element, err = reg.GetInfoElement("destinationIPv4Address")
	if err != nil {
		t.Errorf("Did not find the elements with name sourceIPv4Address")
	}
	mockRecord.EXPECT().AddInfoElement(element, nil).Return(nil)
	if err := mockRecord.AddInfoElement(element, nil); err != nil {
		t.Errorf("Error when adding info element %s: %v", element.Name, err)
	}

	mockRecord.EXPECT().AddInfoElement(element, nil).Return(nil)
	tempRecBuff := mockRecord.GetBuffer()
	tempRecBytes := tempRecBuff.Bytes()

	mockExporter.EXPECT().AddRecordAndSendMsg(entities.Template, &tempRecBytes).Return(len(tempRecBytes), nil)

	mockExporter.AddRecordAndSendMsg(entities.Template, &tempRecBytes)
}*/

func TestExportingProcess_SendingTemplateRecordToLocalServer(t *testing.T) {
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
	exporter.CloseConnToCollector()
}

func TestExportingProcess_SendingDataRecordToLocalServer(t *testing.T) {
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
	exporter.CloseConnToCollector()
}
