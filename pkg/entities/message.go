// Copyright 2020 VMware, Inc.
// SPDX-License-Identifier: Apache-2.0

package entities

import "bytes"

const (
	MaxTcpSocketMsgSize uint16 = 65535
)

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
