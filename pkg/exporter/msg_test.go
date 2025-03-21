// Copyright 2025 VMware, Inc.
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

package exporter

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vmware/go-ipfix/pkg/entities"
	"github.com/vmware/go-ipfix/pkg/registry"
)

func BenchmarkWriteIPFIXMsgToBuffer(b *testing.B) {
	now := time.Now()
	const templateID = 256
	ieSrc, err := registry.GetInfoElement("sourceIPv4Address", registry.IANAEnterpriseID)
	require.NoError(b, err, "Did not find the element with name sourceIPv4Address")
	ieDst, err := registry.GetInfoElement("destinationIPv4Address", registry.IANAEnterpriseID)
	require.NoError(b, err, "Did not find the element with name destinationIPv4Address")
	getDataRecord := func() entities.Record {
		elements := []entities.InfoElementWithValue{
			entities.NewIPAddressInfoElement(ieSrc, net.ParseIP("1.2.3.4")),
			entities.NewIPAddressInfoElement(ieDst, net.ParseIP("5.6.7.8")),
		}
		return entities.NewDataRecordFromElements(templateID, elements)
	}
	buf := bytes.NewBuffer(make([]byte, 0, 512))
	b.ResetTimer()

	for range b.N {
		b.StopTimer()
		dataSet := entities.NewSet(false)
		require.NoError(b, dataSet.PrepareSet(entities.Data, templateID))
		// 10 records in one data set / message seems like a reasonable benchmark.
		const numRecords = 10
		for range numRecords {
			require.NoError(b, dataSet.AddRecordV3(getDataRecord()))
		}
		buf.Reset()
		b.StartTimer()
		n, err := WriteIPFIXMsgToBuffer(dataSet, 1, 1, now, buf)
		require.NoError(b, err)
		assert.Greater(b, n, 0)
	}
}
