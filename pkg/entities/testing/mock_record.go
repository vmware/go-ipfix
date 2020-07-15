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


// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/vmware/go-ipfix/pkg/entities (interfaces: Record)

// Package testing is a generated GoMock package.
package testing

import (
	bytes "bytes"
	gomock "github.com/golang/mock/gomock"
	entities "github.com/vmware/go-ipfix/pkg/entities"
	reflect "reflect"
)

// MockRecord is a mock of Record interface
type MockRecord struct {
	ctrl     *gomock.Controller
	recorder *MockRecordMockRecorder
}

// MockRecordMockRecorder is the mock recorder for MockRecord
type MockRecordMockRecorder struct {
	mock *MockRecord
}

// NewMockRecord creates a new mock instance
func NewMockRecord(ctrl *gomock.Controller) *MockRecord {
	mock := &MockRecord{ctrl: ctrl}
	mock.recorder = &MockRecordMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockRecord) EXPECT() *MockRecordMockRecorder {
	return m.recorder
}

// AddInfoElement mocks base method
func (m *MockRecord) AddInfoElement(arg0 *entities.InfoElement, arg1 interface{}) (uint16, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AddInfoElement", arg0, arg1)
	ret0, _ := ret[0].(uint16)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// AddInfoElement indicates an expected call of AddInfoElement
func (mr *MockRecordMockRecorder) AddInfoElement(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AddInfoElement", reflect.TypeOf((*MockRecord)(nil).AddInfoElement), arg0, arg1)
}

// GetBuffer mocks base method
func (m *MockRecord) GetBuffer() *bytes.Buffer {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetBuffer")
	ret0, _ := ret[0].(*bytes.Buffer)
	return ret0
}

// GetBuffer indicates an expected call of GetBuffer
func (mr *MockRecordMockRecorder) GetBuffer() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetBuffer", reflect.TypeOf((*MockRecord)(nil).GetBuffer))
}

// GetFieldCount mocks base method
func (m *MockRecord) GetFieldCount() uint16 {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetFieldCount")
	ret0, _ := ret[0].(uint16)
	return ret0
}

// GetFieldCount indicates an expected call of GetFieldCount
func (mr *MockRecordMockRecorder) GetFieldCount() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetFieldCount", reflect.TypeOf((*MockRecord)(nil).GetFieldCount))
}

// GetMinDataRecordLen mocks base method
func (m *MockRecord) GetMinDataRecordLen() uint16 {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetMinDataRecordLen")
	ret0, _ := ret[0].(uint16)
	return ret0
}

// GetMinDataRecordLen indicates an expected call of GetMinDataRecordLen
func (mr *MockRecordMockRecorder) GetMinDataRecordLen() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetMinDataRecordLen", reflect.TypeOf((*MockRecord)(nil).GetMinDataRecordLen))
}

// GetTemplateElements mocks base method
func (m *MockRecord) GetTemplateElements() []*entities.InfoElement {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetTemplateElements")
	ret0, _ := ret[0].([]*entities.InfoElement)
	return ret0
}

// GetTemplateElements indicates an expected call of GetTemplateElements
func (mr *MockRecordMockRecorder) GetTemplateElements() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetTemplateElements", reflect.TypeOf((*MockRecord)(nil).GetTemplateElements))
}

// GetTemplateID mocks base method
func (m *MockRecord) GetTemplateID() uint16 {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetTemplateID")
	ret0, _ := ret[0].(uint16)
	return ret0
}

// GetTemplateID indicates an expected call of GetTemplateID
func (mr *MockRecordMockRecorder) GetTemplateID() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetTemplateID", reflect.TypeOf((*MockRecord)(nil).GetTemplateID))
}

// PrepareRecord mocks base method
func (m *MockRecord) PrepareRecord() (uint16, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "PrepareRecord")
	ret0, _ := ret[0].(uint16)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// PrepareRecord indicates an expected call of PrepareRecord
func (mr *MockRecordMockRecorder) PrepareRecord() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "PrepareRecord", reflect.TypeOf((*MockRecord)(nil).PrepareRecord))
}
