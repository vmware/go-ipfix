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

package util

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
)

// Encode writes the multiple inputs of different possible datatypes to the io writer.
func Encode(buff io.Writer, byteOrder binary.ByteOrder, inputs ...interface{}) error {
	var err error
	for _, in := range inputs {
		err = binary.Write(buff, byteOrder, in)
		if err != nil {
			return fmt.Errorf("error in encoding data %v: %v", in, err)
		}
	}
	return nil
}

// Decode decodes data from io reader to specified interfaces
/* Example:
var num1 uint16
var num2 uint32
// read the buffer 2 bytes and 4 bytes sequentially
// decode and output corresponding uint16 and uint32 number into num1 and num2 respectively
err := Decode(buffer, &num1, &num2)
*/
func Decode(buffer io.Reader, byteOrder binary.ByteOrder, outputs ...interface{}) error {
	var err error
	for _, out := range outputs {
		err = binary.Read(buffer, byteOrder, out)
		if err != nil {
			return fmt.Errorf("error in decoding data: %v", err)
		}
	}
	return nil
}

// ResolveDNSAddress gets ip:port or dns:port as input and resolves the dns name if exists
// then return ip:port
func ResolveDNSAddress(address string, isIPv6 bool) (string, error) {
	portIndex := strings.LastIndex(address, ":")
	port := address[portIndex+1:]
	addr := address[:portIndex]
	addr = strings.Replace(addr, "[", "", -1)
	addr = strings.Replace(addr, "]", "", -1)
	if ipAddr := net.ParseIP(addr); ipAddr == nil && len(addr) != 0 { // resolve DNS name
		hostIPs, err := net.LookupIP(addr)
		if err != nil {
			if !isIPv6 {
				if ip := hostIPs[0].To4(); ip != nil {
					return net.JoinHostPort(ip.String(), port), nil
				} else {
					return "", fmt.Errorf("cannot resolve %s to IPv4 address", address)
				}
			} else {
				if ip := hostIPs[0].To16(); ip != nil {
					return net.JoinHostPort(ip.String(), port), nil
				} else {
					return "", fmt.Errorf("cannot resolve %s to IPv6 address", address)
				}
			}
		}
		return "", err
	}
	return address, nil
}
