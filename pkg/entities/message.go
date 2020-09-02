// Copyright 2020 VMware, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package entities

import "bytes"

const (
	MaxTcpSocketMsgSize uint16 = 65535
)

// data struct of processed message
type Message struct {
	Version      uint16
	BufferLength uint16
	SeqNumber    uint32
	ObsDomainID  uint32
	ExportTime   uint32
	Record       interface{}
}

// Does it need an interface?

type MsgBuffer struct {
	buffer      bytes.Buffer
	dataRecFlag bool
}

func NewMsgBuffer() *MsgBuffer {
	return &MsgBuffer{
		buffer:      bytes.Buffer{},
		dataRecFlag: false,
	}
}

func (m *MsgBuffer) GetMsgBuffer() *bytes.Buffer {
	return &m.buffer
}

func (m *MsgBuffer) GetDataRecFlag() bool {
	return m.dataRecFlag
}

func (m *MsgBuffer) SetDataRecFlag(flag bool) {
	m.dataRecFlag = flag
}

type templateMessage struct {
	// enterpriseID -> elementID
	elements map[uint32][]uint16
}

type dataMessage struct {
	// enterpriseID -> elementID -> val
	elements map[uint32]map[uint16]interface{}
}

func NewTemplateMessage() *templateMessage {
	return &templateMessage{
		make(map[uint32][]uint16),
	}
}

func NewDataMessage() *dataMessage {
	return &dataMessage{
		make(map[uint32]map[uint16]interface{}),
	}
}

func (d *dataMessage) AddInfoElement(enterpriseID uint32, elementID uint16, val []byte) {
	if _, exist := d.elements[enterpriseID]; !exist {
		d.elements[enterpriseID] = make(map[uint16]interface{})
	}
	// TODO: Decode data using element datatype
	d.elements[enterpriseID][elementID] = val
}

func (t *templateMessage) AddInfoElement(enterpriseID uint32, elementID uint16) {
	if _, exist := t.elements[enterpriseID]; !exist {
		t.elements[enterpriseID] = make([]uint16, 0)
	}
	t.elements[enterpriseID] = append(t.elements[enterpriseID], elementID)
}
