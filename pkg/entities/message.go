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
	Set          Set
}

// Does it need an interface?

type MsgBuffer struct {
	buffer       bytes.Buffer
	dataRecFlag  bool
}

func NewMsgBuffer() *MsgBuffer {
	return &MsgBuffer{
		buffer:       bytes.Buffer{},
		dataRecFlag:  false,
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
