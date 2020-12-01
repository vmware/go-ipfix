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

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestMessage_SetAndGetFunctions(t *testing.T) {
	set := NewSet(Data, 257, false)

	message := NewMessage(false)
	message.CreateHeader()

	message.SetVersion(10)
	assert.Equal(t, message.GetVersion(), uint16(10))
	assert.Equal(t, binary.BigEndian.Uint16(message.GetMsgBuffer().Bytes()[0:2]), uint16(10))
	message.SetMessageLen(32)
	assert.Equal(t, message.GetMessageLen(), uint16(32))
	assert.Equal(t, binary.BigEndian.Uint16(message.GetMsgBuffer().Bytes()[2:4]), uint16(32))
	message.SetSequenceNum(1)
	assert.Equal(t, message.GetSequenceNum(), uint32(1))
	assert.Equal(t, binary.BigEndian.Uint32(message.GetMsgBuffer().Bytes()[8:12]), uint32(1))
	message.SetObsDomainID(1234)
	assert.Equal(t, message.GetObsDomainID(), uint32(1234))
	assert.Equal(t, binary.BigEndian.Uint32(message.GetMsgBuffer().Bytes()[12:]), uint32(1234))
	currTimeInUnixSecs := uint32(time.Now().Unix())
	message.SetExportTime(currTimeInUnixSecs)
	assert.Equal(t, message.GetExportTime(), currTimeInUnixSecs)
	assert.Equal(t, binary.BigEndian.Uint32(message.GetMsgBuffer().Bytes()[4:8]), currTimeInUnixSecs)
	message.SetExportAddress("127.0.0.1")
	assert.Equal(t, message.GetExportAddress(), "127.0.0.1")
	message.AddSet(set)
	assert.Equal(t, message.GetSet(), set)
	message.ResetMsgBuffer()
	assert.Equal(t, message.GetMsgBufferLen(), 0)
}
