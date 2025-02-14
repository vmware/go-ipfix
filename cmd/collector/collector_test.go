// Copyright 2024 Broadcom, Inc.
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

package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vmware/go-ipfix/pkg/entities"
)

const templateID = 256

var (
	flow1 = &flowRecord{
		Data: "flow1",
	}
	flow2 = &flowRecord{
		Data: "flow2",
	}
	flow3 = &flowRecord{
		Data: "flow3",
	}
)

var testFlowRecords = []*flowRecord{flow1, flow2, flow3}

func TestFlowRecordHandler(t *testing.T) {
	flowRecords = testFlowRecords
	defer func() {
		flowRecords = nil
	}()

	testCases := []struct {
		name           string
		countParam     string
		formatParam    string
		expectedStatus int
		expectedFlows  []*flowRecord
	}{
		{
			name:          "default",
			expectedFlows: []*flowRecord{flow1, flow2, flow3},
		},
		{
			name:          "last flow",
			countParam:    "1",
			expectedFlows: []*flowRecord{flow3},
		},
		{
			name:          "text format",
			formatParam:   "text",
			expectedFlows: []*flowRecord{flow1, flow2, flow3},
		},
		{
			name:          "json format",
			formatParam:   "json",
			expectedFlows: []*flowRecord{flow1, flow2, flow3},
		},
		{
			name:          "large count",
			countParam:    "100",
			expectedFlows: []*flowRecord{flow1, flow2, flow3},
		},
		{
			name:           "invalid count",
			countParam:     "-1",
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "invalid format",
			formatParam:    "foobar",
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:          "both params set",
			countParam:    "2",
			formatParam:   "text",
			expectedFlows: []*flowRecord{flow2, flow3},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			expectedStatus := tc.expectedStatus
			if expectedStatus == 0 {
				expectedStatus = http.StatusOK
			}
			format := tc.formatParam
			if format == "" {
				format = "json"
			}
			rr := httptest.NewRecorder()
			u := url.URL{
				Path: "/records",
			}
			q := u.Query()
			if tc.countParam != "" {
				q.Set("count", tc.countParam)
			}
			if tc.formatParam != "" {
				q.Set("format", tc.formatParam)
			}
			u.RawQuery = q.Encode()
			req, err := http.NewRequest("GET", u.String(), nil)
			require.NoError(t, err)
			flowRecordHandler(rr, req)
			resp := rr.Result()
			defer resp.Body.Close()
			require.Equal(t, expectedStatus, resp.StatusCode)
			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)

			if expectedStatus != http.StatusOK {
				return
			}

			contentType := resp.Header.Get("Content-type")
			if format == "json" {
				require.Equal(t, "application/json", contentType)
				var data jsonResponse
				err := json.Unmarshal(body, &data)
				require.NoError(t, err, "Invalid JSON response")
				assert.Equal(t, tc.expectedFlows, data.FlowRecords)
			} else if format == "text" {
				require.Equal(t, "text/plain", contentType)
				expectedFlows := ""
				for _, flow := range tc.expectedFlows {
					expectedFlows += flow.Data + string(flowTextSeparator)
				}
				assert.Equal(t, expectedFlows, string(body))
			} else {
				require.FailNow(t, "Invalid format specified for test case")
			}
		})
	}
}

func TestAddIPFIXMessage(t *testing.T) {
	defer func() {
		flowRecords = nil
	}()
	var buf bytes.Buffer
	set := entities.NewSet(false)
	require.NoError(t, set.PrepareSet(entities.Data, templateID))
	require.NoError(t, set.AddRecord([]entities.InfoElementWithValue{}, templateID))
	msg := entities.NewMessage(false)
	msg.AddSet(set)
	for i := 0; i < maxFlowRecords; i++ {
		addIPFIXMessage(msg, &buf)
		require.Len(t, flowRecords, i+1)
	}
	addIPFIXMessage(msg, &buf)
	assert.Len(t, flowRecords, maxFlowRecords)
}

func TestAddIPFIXMessageMultipleDataRecords(t *testing.T) {
	defer func() {
		flowRecords = nil
	}()
	var buf bytes.Buffer
	set := entities.NewSet(false)
	require.NoError(t, set.PrepareSet(entities.Data, templateID))
	require.NoError(t, set.AddRecord([]entities.InfoElementWithValue{}, templateID))
	require.NoError(t, set.AddRecord([]entities.InfoElementWithValue{}, templateID))
	msg := entities.NewMessage(false)
	msg.AddSet(set)
	addIPFIXMessage(msg, &buf)
	require.Len(t, flowRecords, 2)
	assert.EqualValues(t, 0, flowRecords[0].RecordIdx)
	assert.EqualValues(t, 1, flowRecords[1].RecordIdx)
}
