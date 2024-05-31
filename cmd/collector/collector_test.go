// Copyright 2024 VMware, Inc.
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
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vmware/go-ipfix/pkg/entities"
)

var testFlowRecords = []string{"flow1", "flow2", "flow3"}

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
		expectedFlows  []string
	}{
		{
			name:          "default",
			expectedFlows: []string{"flow1", "flow2", "flow3"},
		},
		{
			name:          "last flow",
			countParam:    "1",
			expectedFlows: []string{"flow3"},
		},
		{
			name:          "text format",
			formatParam:   "text",
			expectedFlows: []string{"flow1", "flow2", "flow3"},
		},
		{
			name:          "json format",
			formatParam:   "json",
			expectedFlows: []string{"flow1", "flow2", "flow3"},
		},
		{
			name:          "large count",
			countParam:    "100",
			expectedFlows: []string{"flow1", "flow2", "flow3"},
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
			expectedFlows: []string{"flow1", "flow2"},
		},
	}

	for _, tc := range testCases {
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
			flows := strings.Split(string(body), string(flowTextSeparator))
			// Ignore the last empty fragment.
			assert.Equal(t, tc.expectedFlows, flows[:len(flows)-1])
		} else {
			require.FailNow(t, "Invalid format specified for test case")
		}
	}
}

func TestAddIPFIXMessage(t *testing.T) {
	defer func() {
		flowRecords = nil
	}()
	set := entities.NewSet(false)
	msg := entities.NewMessage(false)
	msg.AddSet(set)
	for i := 0; i < maxFlowRecords; i++ {
		addIPFIXMessage(msg)
		require.Len(t, flowRecords, i+1)
	}
	addIPFIXMessage(msg)
	assert.Len(t, flowRecords, maxFlowRecords)
}
