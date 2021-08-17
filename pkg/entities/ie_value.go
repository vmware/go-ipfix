package entities

import (
	"fmt"
	"net"
)

type InfoElementWithValue interface {
	// GetInfoElement retrieves the info element. This is called after AddInfoElement.
	// TODO: Handle error to make it more robust if it is called prior to AddInfoElement.
	GetInfoElement() *InfoElement
	AddInfoElement(infoElement *InfoElement)
	GetUnsigned8Value() (uint8, error)
	GetUnsigned16Value() (uint16, error)
	GetUnsigned32Value() (uint32, error)
	GetUnsigned64Value() (uint64, error)
	GetSigned8Value() (int8, error)
	GetSigned16Value() (int16, error)
	GetSigned32Value() (int32, error)
	GetSigned64Value() (int64, error)
	GetFloat32Value() (float32, error)
	GetFloat64Value() (float64, error)
	GetBooleanValue() (bool, error)
	GetMacAddressValue() (net.HardwareAddr, error)
	GetStringValue() (string, error)
	GetIPAddressValue() (net.IP, error)
	SetUnsigned8Value(val uint8) error
	SetUnsigned16Value(val uint16) error
	SetUnsigned32Value(val uint32) error
	SetUnsigned64Value(val uint64) error
	SetSigned8Value(val int8) error
	SetSigned16Value(val int16) error
	SetSigned32Value(val int32) error
	SetSigned64Value(val int64) error
	SetFloat32Value(val float32) error
	SetFloat64Value(val float64) error
	SetBooleanValue(val bool) error
	SetMacAddressValue(val net.HardwareAddr) error
	SetStringValue(val string) error
	SetIPAddressValue(val net.IP) error
	IsValueEmpty() bool
	GetLength() int
	ResetValue()
}

type Unsigned8InfoElement struct {
	value   uint8
	element *InfoElement
}

func NewUnsigned8InfoElement(element *InfoElement, val uint8) *Unsigned8InfoElement {
	return &Unsigned8InfoElement{
		element: element,
		value:   val,
	}
}

func (u8 *Unsigned8InfoElement) GetInfoElement() *InfoElement {
	return u8.element
}

func (u8 *Unsigned8InfoElement) AddInfoElement(infoElement *InfoElement) {
	u8.element = infoElement
}

func (u8 *Unsigned8InfoElement) GetUnsigned8Value() (uint8, error) {
	return u8.value, nil
}

func (u8 *Unsigned8InfoElement) GetUnsigned16Value() (uint16, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (u8 *Unsigned8InfoElement) GetUnsigned32Value() (uint32, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (u8 *Unsigned8InfoElement) GetUnsigned64Value() (uint64, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (u8 *Unsigned8InfoElement) GetSigned8Value() (int8, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (u8 *Unsigned8InfoElement) GetSigned16Value() (int16, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (u8 *Unsigned8InfoElement) GetSigned32Value() (int32, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (u8 *Unsigned8InfoElement) GetSigned64Value() (int64, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (u8 *Unsigned8InfoElement) GetFloat32Value() (float32, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (u8 *Unsigned8InfoElement) GetFloat64Value() (float64, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (u8 *Unsigned8InfoElement) GetBooleanValue() (bool, error) {
	return false, fmt.Errorf("accessing value of wrong data type")
}

func (u8 *Unsigned8InfoElement) GetMacAddressValue() (net.HardwareAddr, error) {
	return nil, fmt.Errorf("accessing value of wrong data type")
}

func (u8 *Unsigned8InfoElement) GetStringValue() (string, error) {
	return "", fmt.Errorf("accessing value of wrong data type")
}

func (u8 *Unsigned8InfoElement) GetIPAddressValue() (net.IP, error) {
	return nil, fmt.Errorf("accessing value of wrong data type")
}

func (u8 *Unsigned8InfoElement) SetUnsigned8Value(val uint8) error {
	u8.value = val
	return nil
}

func (u8 *Unsigned8InfoElement) SetUnsigned16Value(val uint16) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (u8 *Unsigned8InfoElement) SetUnsigned32Value(val uint32) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (u8 *Unsigned8InfoElement) SetUnsigned64Value(val uint64) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (u8 *Unsigned8InfoElement) SetSigned8Value(val int8) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (u8 *Unsigned8InfoElement) SetSigned16Value(val int16) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (u8 *Unsigned8InfoElement) SetSigned32Value(val int32) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (u8 *Unsigned8InfoElement) SetSigned64Value(val int64) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (u8 *Unsigned8InfoElement) SetFloat32Value(val float32) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (u8 *Unsigned8InfoElement) SetFloat64Value(val float64) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (u8 *Unsigned8InfoElement) SetBooleanValue(val bool) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (u8 *Unsigned8InfoElement) SetMacAddressValue(val net.HardwareAddr) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (u8 *Unsigned8InfoElement) SetStringValue(val string) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (u8 *Unsigned8InfoElement) SetIPAddressValue(val net.IP) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (u8 *Unsigned8InfoElement) IsValueEmpty() bool {
	return u8.value == 0
}

func (u8 *Unsigned8InfoElement) GetLength() int {
	return int(u8.element.Len)
}

func (u8 *Unsigned8InfoElement) ResetValue() {
	u8.value = 0
}

type Unsigned16InfoElement struct {
	value   uint16
	element *InfoElement
}

func NewUnsigned16InfoElement(element *InfoElement, val uint16) *Unsigned16InfoElement {
	return &Unsigned16InfoElement{
		element: element,
		value:   val,
	}
}

func (u16 *Unsigned16InfoElement) GetInfoElement() *InfoElement {
	return u16.element
}

func (u16 *Unsigned16InfoElement) AddInfoElement(infoElement *InfoElement) {
	u16.element = infoElement
}

func (u16 *Unsigned16InfoElement) GetUnsigned8Value() (uint8, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (u16 *Unsigned16InfoElement) GetUnsigned16Value() (uint16, error) {
	return u16.value, nil
}

func (u16 *Unsigned16InfoElement) GetUnsigned32Value() (uint32, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (u16 *Unsigned16InfoElement) GetUnsigned64Value() (uint64, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (u16 *Unsigned16InfoElement) GetSigned8Value() (int8, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (u16 *Unsigned16InfoElement) GetSigned16Value() (int16, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (u16 *Unsigned16InfoElement) GetSigned32Value() (int32, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (u16 *Unsigned16InfoElement) GetSigned64Value() (int64, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (u16 *Unsigned16InfoElement) GetFloat32Value() (float32, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (u16 *Unsigned16InfoElement) GetFloat64Value() (float64, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (u16 *Unsigned16InfoElement) GetBooleanValue() (bool, error) {
	return false, fmt.Errorf("accessing value of wrong data type")
}

func (u16 *Unsigned16InfoElement) GetMacAddressValue() (net.HardwareAddr, error) {
	return nil, fmt.Errorf("accessing value of wrong data type")
}

func (u16 *Unsigned16InfoElement) GetStringValue() (string, error) {
	return "", fmt.Errorf("accessing value of wrong data type")
}

func (u16 *Unsigned16InfoElement) GetIPAddressValue() (net.IP, error) {
	return nil, fmt.Errorf("accessing value of wrong data type")
}

func (u16 *Unsigned16InfoElement) SetUnsigned8Value(val uint8) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (u16 *Unsigned16InfoElement) SetUnsigned16Value(val uint16) error {
	u16.value = val
	return nil
}

func (u16 *Unsigned16InfoElement) SetUnsigned32Value(val uint32) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (u16 *Unsigned16InfoElement) SetUnsigned64Value(val uint64) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (u16 *Unsigned16InfoElement) SetSigned8Value(val int8) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (u16 *Unsigned16InfoElement) SetSigned16Value(val int16) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (u16 *Unsigned16InfoElement) SetSigned32Value(val int32) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (u16 *Unsigned16InfoElement) SetSigned64Value(val int64) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (u16 *Unsigned16InfoElement) SetFloat32Value(val float32) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (u16 *Unsigned16InfoElement) SetFloat64Value(val float64) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (u16 *Unsigned16InfoElement) SetBooleanValue(val bool) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (u16 *Unsigned16InfoElement) SetMacAddressValue(val net.HardwareAddr) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (u16 *Unsigned16InfoElement) SetStringValue(val string) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (u16 *Unsigned16InfoElement) SetIPAddressValue(val net.IP) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (u16 *Unsigned16InfoElement) IsValueEmpty() bool {
	return u16.value == 0
}

func (u16 *Unsigned16InfoElement) GetLength() int {
	return int(u16.element.Len)
}

func (u16 *Unsigned16InfoElement) ResetValue() {
	u16.value = 0
}

type Unsigned32InfoElement struct {
	value   uint32
	element *InfoElement
}

func NewUnsigned32InfoElement(element *InfoElement, val uint32) *Unsigned32InfoElement {
	return &Unsigned32InfoElement{
		element: element,
		value:   val,
	}
}

func (u32 *Unsigned32InfoElement) GetInfoElement() *InfoElement {
	return u32.element
}

func (u32 *Unsigned32InfoElement) AddInfoElement(infoElement *InfoElement) {
	u32.element = infoElement
}

func (u32 *Unsigned32InfoElement) GetUnsigned8Value() (uint8, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (u32 *Unsigned32InfoElement) GetUnsigned16Value() (uint16, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (u32 *Unsigned32InfoElement) GetUnsigned32Value() (uint32, error) {
	return u32.value, nil
}

func (u32 *Unsigned32InfoElement) GetUnsigned64Value() (uint64, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (u32 *Unsigned32InfoElement) GetSigned8Value() (int8, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (u32 *Unsigned32InfoElement) GetSigned16Value() (int16, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (u32 *Unsigned32InfoElement) GetSigned32Value() (int32, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (u32 *Unsigned32InfoElement) GetSigned64Value() (int64, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (u32 *Unsigned32InfoElement) GetFloat32Value() (float32, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (u32 *Unsigned32InfoElement) GetFloat64Value() (float64, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (u32 *Unsigned32InfoElement) GetBooleanValue() (bool, error) {
	return false, fmt.Errorf("accessing value of wrong data type")
}

func (u32 *Unsigned32InfoElement) GetMacAddressValue() (net.HardwareAddr, error) {
	return nil, fmt.Errorf("accessing value of wrong data type")
}

func (u32 *Unsigned32InfoElement) GetStringValue() (string, error) {
	return "", fmt.Errorf("accessing value of wrong data type")
}

func (u32 *Unsigned32InfoElement) GetIPAddressValue() (net.IP, error) {
	return nil, fmt.Errorf("accessing value of wrong data type")
}

func (u32 *Unsigned32InfoElement) SetUnsigned8Value(val uint8) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (u32 *Unsigned32InfoElement) SetUnsigned16Value(val uint16) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (u32 *Unsigned32InfoElement) SetUnsigned32Value(val uint32) error {
	u32.value = val
	return nil
}

func (u32 *Unsigned32InfoElement) SetUnsigned64Value(val uint64) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (u32 *Unsigned32InfoElement) SetSigned8Value(val int8) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (u32 *Unsigned32InfoElement) SetSigned16Value(val int16) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (u32 *Unsigned32InfoElement) SetSigned32Value(val int32) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (u32 *Unsigned32InfoElement) SetSigned64Value(val int64) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (u32 *Unsigned32InfoElement) SetFloat32Value(val float32) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (u32 *Unsigned32InfoElement) SetFloat64Value(val float64) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (u32 *Unsigned32InfoElement) SetBooleanValue(val bool) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (u32 *Unsigned32InfoElement) SetMacAddressValue(val net.HardwareAddr) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (u32 *Unsigned32InfoElement) SetStringValue(val string) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (u32 *Unsigned32InfoElement) SetIPAddressValue(val net.IP) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (u32 *Unsigned32InfoElement) IsValueEmpty() bool {
	return u32.value == 0
}

func (u32 *Unsigned32InfoElement) GetLength() int {
	return int(u32.element.Len)
}

func (u32 *Unsigned32InfoElement) ResetValue() {
	u32.value = 0
}

type Unsigned64InfoElement struct {
	value   uint64
	element *InfoElement
}

func NewUnsigned64InfoElement(element *InfoElement, val uint64) *Unsigned64InfoElement {
	return &Unsigned64InfoElement{
		element: element,
		value:   val,
	}
}

func (u64 *Unsigned64InfoElement) GetInfoElement() *InfoElement {
	return u64.element
}

func (u64 *Unsigned64InfoElement) AddInfoElement(infoElement *InfoElement) {
	u64.element = infoElement
}

func (u64 *Unsigned64InfoElement) GetUnsigned8Value() (uint8, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (u64 *Unsigned64InfoElement) GetUnsigned16Value() (uint16, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (u64 *Unsigned64InfoElement) GetUnsigned32Value() (uint32, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (u64 *Unsigned64InfoElement) GetUnsigned64Value() (uint64, error) {
	return u64.value, nil
}

func (u64 *Unsigned64InfoElement) GetSigned8Value() (int8, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (u64 *Unsigned64InfoElement) GetSigned16Value() (int16, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (u64 *Unsigned64InfoElement) GetSigned32Value() (int32, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (u64 *Unsigned64InfoElement) GetSigned64Value() (int64, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (u64 *Unsigned64InfoElement) GetFloat32Value() (float32, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (u64 *Unsigned64InfoElement) GetFloat64Value() (float64, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (u64 *Unsigned64InfoElement) GetBooleanValue() (bool, error) {
	return false, fmt.Errorf("accessing value of wrong data type")
}

func (u64 *Unsigned64InfoElement) GetMacAddressValue() (net.HardwareAddr, error) {
	return nil, fmt.Errorf("accessing value of wrong data type")
}

func (u64 *Unsigned64InfoElement) GetStringValue() (string, error) {
	return "", fmt.Errorf("accessing value of wrong data type")
}

func (u64 *Unsigned64InfoElement) GetIPAddressValue() (net.IP, error) {
	return nil, fmt.Errorf("accessing value of wrong data type")
}

func (u64 *Unsigned64InfoElement) SetUnsigned8Value(val uint8) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (u64 *Unsigned64InfoElement) SetUnsigned16Value(val uint16) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (u64 *Unsigned64InfoElement) SetUnsigned32Value(val uint32) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (u64 *Unsigned64InfoElement) SetUnsigned64Value(val uint64) error {
	u64.value = val
	return nil
}

func (u64 *Unsigned64InfoElement) SetSigned8Value(val int8) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (u64 *Unsigned64InfoElement) SetSigned16Value(val int16) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (u64 *Unsigned64InfoElement) SetSigned32Value(val int32) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (u64 *Unsigned64InfoElement) SetSigned64Value(val int64) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (u64 *Unsigned64InfoElement) SetFloat32Value(val float32) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (u64 *Unsigned64InfoElement) SetFloat64Value(val float64) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (u64 *Unsigned64InfoElement) SetBooleanValue(val bool) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (u64 *Unsigned64InfoElement) SetMacAddressValue(val net.HardwareAddr) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (u64 *Unsigned64InfoElement) SetStringValue(val string) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (u64 *Unsigned64InfoElement) SetIPAddressValue(val net.IP) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (u64 *Unsigned64InfoElement) IsValueEmpty() bool {
	return u64.value == 0
}

func (u64 *Unsigned64InfoElement) GetLength() int {
	return int(u64.element.Len)
}

func (u64 *Unsigned64InfoElement) ResetValue() {
	u64.value = 0
}

type Signed8InfoElement struct {
	value   int8
	element *InfoElement
}

func NewSigned8InfoElement(element *InfoElement, val int8) *Signed8InfoElement {
	return &Signed8InfoElement{
		element: element,
		value:   val,
	}
}

func (i8 *Signed8InfoElement) GetInfoElement() *InfoElement {
	return i8.element
}

func (i8 *Signed8InfoElement) AddInfoElement(infoElement *InfoElement) {
	i8.element = infoElement
}

func (i8 *Signed8InfoElement) GetUnsigned8Value() (uint8, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (i8 *Signed8InfoElement) GetUnsigned16Value() (uint16, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (i8 *Signed8InfoElement) GetUnsigned32Value() (uint32, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (i8 *Signed8InfoElement) GetUnsigned64Value() (uint64, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (i8 *Signed8InfoElement) GetSigned8Value() (int8, error) {
	return i8.value, nil
}

func (i8 *Signed8InfoElement) GetSigned16Value() (int16, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (i8 *Signed8InfoElement) GetSigned32Value() (int32, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (i8 *Signed8InfoElement) GetSigned64Value() (int64, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (i8 *Signed8InfoElement) GetFloat32Value() (float32, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (i8 *Signed8InfoElement) GetFloat64Value() (float64, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (i8 *Signed8InfoElement) GetBooleanValue() (bool, error) {
	return false, fmt.Errorf("accessing value of wrong data type")
}

func (i8 *Signed8InfoElement) GetMacAddressValue() (net.HardwareAddr, error) {
	return nil, fmt.Errorf("accessing value of wrong data type")
}

func (i8 *Signed8InfoElement) GetStringValue() (string, error) {
	return "", fmt.Errorf("accessing value of wrong data type")
}

func (i8 *Signed8InfoElement) GetIPAddressValue() (net.IP, error) {
	return nil, fmt.Errorf("accessing value of wrong data type")
}

func (i8 *Signed8InfoElement) SetUnsigned8Value(val uint8) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (i8 *Signed8InfoElement) SetUnsigned16Value(val uint16) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (i8 *Signed8InfoElement) SetUnsigned32Value(val uint32) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (i8 *Signed8InfoElement) SetUnsigned64Value(val uint64) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (i8 *Signed8InfoElement) SetSigned8Value(val int8) error {
	i8.value = val
	return nil
}

func (i8 *Signed8InfoElement) SetSigned16Value(val int16) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (i8 *Signed8InfoElement) SetSigned32Value(val int32) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (i8 *Signed8InfoElement) SetSigned64Value(val int64) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (i8 *Signed8InfoElement) SetFloat32Value(val float32) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (i8 *Signed8InfoElement) SetFloat64Value(val float64) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (i8 *Signed8InfoElement) SetBooleanValue(val bool) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (i8 *Signed8InfoElement) SetMacAddressValue(val net.HardwareAddr) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (i8 *Signed8InfoElement) SetStringValue(val string) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (i8 *Signed8InfoElement) SetIPAddressValue(val net.IP) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (i8 *Signed8InfoElement) IsValueEmpty() bool {
	return i8.value == 0
}

func (i8 *Signed8InfoElement) GetLength() int {
	return int(i8.element.Len)
}

func (i8 *Signed8InfoElement) ResetValue() {
	i8.value = 0
}

type Signed16InfoElement struct {
	value   int16
	element *InfoElement
}

func NewSigned16InfoElement(element *InfoElement, val int16) *Signed16InfoElement {
	return &Signed16InfoElement{
		element: element,
		value:   val,
	}
}

func (i16 *Signed16InfoElement) GetInfoElement() *InfoElement {
	return i16.element
}

func (i16 *Signed16InfoElement) AddInfoElement(infoElement *InfoElement) {
	i16.element = infoElement
}

func (i16 *Signed16InfoElement) GetUnsigned8Value() (uint8, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (i16 *Signed16InfoElement) GetUnsigned16Value() (uint16, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (i16 *Signed16InfoElement) GetUnsigned32Value() (uint32, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (i16 *Signed16InfoElement) GetUnsigned64Value() (uint64, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (i16 *Signed16InfoElement) GetSigned8Value() (int8, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (i16 *Signed16InfoElement) GetSigned16Value() (int16, error) {
	return i16.value, nil
}

func (i16 *Signed16InfoElement) GetSigned32Value() (int32, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (i16 *Signed16InfoElement) GetSigned64Value() (int64, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (i16 *Signed16InfoElement) GetFloat32Value() (float32, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (i16 *Signed16InfoElement) GetFloat64Value() (float64, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (i16 *Signed16InfoElement) GetBooleanValue() (bool, error) {
	return false, fmt.Errorf("accessing value of wrong data type")
}

func (i16 *Signed16InfoElement) GetMacAddressValue() (net.HardwareAddr, error) {
	return nil, fmt.Errorf("accessing value of wrong data type")
}

func (i16 *Signed16InfoElement) GetStringValue() (string, error) {
	return "", fmt.Errorf("accessing value of wrong data type")
}

func (i16 *Signed16InfoElement) GetIPAddressValue() (net.IP, error) {
	return nil, fmt.Errorf("accessing value of wrong data type")
}

func (i16 *Signed16InfoElement) SetUnsigned8Value(val uint8) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (i16 *Signed16InfoElement) SetUnsigned16Value(val uint16) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (i16 *Signed16InfoElement) SetUnsigned32Value(val uint32) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (i16 *Signed16InfoElement) SetUnsigned64Value(val uint64) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (i16 *Signed16InfoElement) SetSigned8Value(val int8) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (i16 *Signed16InfoElement) SetSigned16Value(val int16) error {
	i16.value = val
	return nil
}

func (i16 *Signed16InfoElement) SetSigned32Value(val int32) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (i16 *Signed16InfoElement) SetSigned64Value(val int64) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (i16 *Signed16InfoElement) SetFloat32Value(val float32) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (i16 *Signed16InfoElement) SetFloat64Value(val float64) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (i16 *Signed16InfoElement) SetBooleanValue(val bool) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (i16 *Signed16InfoElement) SetMacAddressValue(val net.HardwareAddr) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (i16 *Signed16InfoElement) SetStringValue(val string) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (i16 *Signed16InfoElement) SetIPAddressValue(val net.IP) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (i16 *Signed16InfoElement) IsValueEmpty() bool {
	return i16.value == 0
}

func (i16 *Signed16InfoElement) GetLength() int {
	return int(i16.element.Len)
}

func (i16 *Signed16InfoElement) ResetValue() {
	i16.value = 0
}

type Signed32InfoElement struct {
	value   int32
	element *InfoElement
}

func NewSigned32InfoElement(element *InfoElement, val int32) *Signed32InfoElement {
	return &Signed32InfoElement{
		element: element,
		value:   val,
	}
}

func (i32 *Signed32InfoElement) GetInfoElement() *InfoElement {
	return i32.element
}

func (i32 *Signed32InfoElement) AddInfoElement(infoElement *InfoElement) {
	i32.element = infoElement
}

func (i32 *Signed32InfoElement) GetUnsigned8Value() (uint8, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (i32 *Signed32InfoElement) GetUnsigned16Value() (uint16, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (i32 *Signed32InfoElement) GetUnsigned32Value() (uint32, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (i32 *Signed32InfoElement) GetUnsigned64Value() (uint64, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (i32 *Signed32InfoElement) GetSigned8Value() (int8, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (i32 *Signed32InfoElement) GetSigned16Value() (int16, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (i32 *Signed32InfoElement) GetSigned32Value() (int32, error) {
	return i32.value, nil
}

func (i32 *Signed32InfoElement) GetSigned64Value() (int64, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (i32 *Signed32InfoElement) GetFloat32Value() (float32, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (i32 *Signed32InfoElement) GetFloat64Value() (float64, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (i32 *Signed32InfoElement) GetBooleanValue() (bool, error) {
	return false, fmt.Errorf("accessing value of wrong data type")
}

func (i32 *Signed32InfoElement) GetMacAddressValue() (net.HardwareAddr, error) {
	return nil, fmt.Errorf("accessing value of wrong data type")
}

func (i32 *Signed32InfoElement) GetStringValue() (string, error) {
	return "", fmt.Errorf("accessing value of wrong data type")
}

func (i32 *Signed32InfoElement) GetIPAddressValue() (net.IP, error) {
	return nil, fmt.Errorf("accessing value of wrong data type")
}

func (i32 *Signed32InfoElement) SetUnsigned8Value(val uint8) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (i32 *Signed32InfoElement) SetUnsigned16Value(val uint16) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (i32 *Signed32InfoElement) SetUnsigned32Value(val uint32) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (i32 *Signed32InfoElement) SetUnsigned64Value(val uint64) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (i32 *Signed32InfoElement) SetSigned8Value(val int8) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (i32 *Signed32InfoElement) SetSigned16Value(val int16) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (i32 *Signed32InfoElement) SetSigned32Value(val int32) error {
	i32.value = val
	return nil
}

func (i32 *Signed32InfoElement) SetSigned64Value(val int64) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (i32 *Signed32InfoElement) SetFloat32Value(val float32) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (i32 *Signed32InfoElement) SetFloat64Value(val float64) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (i32 *Signed32InfoElement) SetBooleanValue(val bool) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (i32 *Signed32InfoElement) SetMacAddressValue(val net.HardwareAddr) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (i32 *Signed32InfoElement) SetStringValue(val string) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (i32 *Signed32InfoElement) SetIPAddressValue(val net.IP) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (i32 *Signed32InfoElement) IsValueEmpty() bool {
	return i32.value == 0
}

func (i32 *Signed32InfoElement) GetLength() int {
	return int(i32.element.Len)
}

func (i32 *Signed32InfoElement) ResetValue() {
	i32.value = 0
}

type Signed64InfoElement struct {
	value   int64
	element *InfoElement
}

func NewSigned64InfoElement(element *InfoElement, val int64) *Signed64InfoElement {
	return &Signed64InfoElement{
		element: element,
		value:   val,
	}
}

func (i64 *Signed64InfoElement) GetInfoElement() *InfoElement {
	return i64.element
}

func (i64 *Signed64InfoElement) AddInfoElement(infoElement *InfoElement) {
	i64.element = infoElement
}

func (i64 *Signed64InfoElement) GetUnsigned8Value() (uint8, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (i64 *Signed64InfoElement) GetUnsigned16Value() (uint16, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (i64 *Signed64InfoElement) GetUnsigned32Value() (uint32, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (i64 *Signed64InfoElement) GetUnsigned64Value() (uint64, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (i64 *Signed64InfoElement) GetSigned8Value() (int8, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (i64 *Signed64InfoElement) GetSigned16Value() (int16, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (i64 *Signed64InfoElement) GetSigned32Value() (int32, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (i64 *Signed64InfoElement) GetSigned64Value() (int64, error) {
	return i64.value, nil
}

func (i64 *Signed64InfoElement) GetFloat32Value() (float32, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (i64 *Signed64InfoElement) GetFloat64Value() (float64, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (i64 *Signed64InfoElement) GetBooleanValue() (bool, error) {
	return false, fmt.Errorf("accessing value of wrong data type")
}

func (i64 *Signed64InfoElement) GetMacAddressValue() (net.HardwareAddr, error) {
	return nil, fmt.Errorf("accessing value of wrong data type")
}

func (i64 *Signed64InfoElement) GetStringValue() (string, error) {
	return "", fmt.Errorf("accessing value of wrong data type")
}

func (i64 *Signed64InfoElement) GetIPAddressValue() (net.IP, error) {
	return nil, fmt.Errorf("accessing value of wrong data type")
}

func (i64 *Signed64InfoElement) SetUnsigned8Value(val uint8) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (i64 *Signed64InfoElement) SetUnsigned16Value(val uint16) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (i64 *Signed64InfoElement) SetUnsigned32Value(val uint32) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (i64 *Signed64InfoElement) SetUnsigned64Value(val uint64) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (i64 *Signed64InfoElement) SetSigned8Value(val int8) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (i64 *Signed64InfoElement) SetSigned16Value(val int16) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (i64 *Signed64InfoElement) SetSigned32Value(val int32) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (i64 *Signed64InfoElement) SetSigned64Value(val int64) error {
	i64.value = val
	return nil
}

func (i64 *Signed64InfoElement) SetFloat32Value(val float32) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (i64 *Signed64InfoElement) SetFloat64Value(val float64) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (i64 *Signed64InfoElement) SetBooleanValue(val bool) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (i64 *Signed64InfoElement) SetMacAddressValue(val net.HardwareAddr) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (i64 *Signed64InfoElement) SetStringValue(val string) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (i64 *Signed64InfoElement) SetIPAddressValue(val net.IP) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (i64 *Signed64InfoElement) IsValueEmpty() bool {
	return i64.value == 0
}

func (i64 *Signed64InfoElement) GetLength() int {
	return int(i64.element.Len)
}

func (i64 *Signed64InfoElement) ResetValue() {
	i64.value = 0
}

type Float32InfoElement struct {
	value   float32
	element *InfoElement
}

func NewFloat32InfoElement(element *InfoElement, val float32) *Float32InfoElement {
	return &Float32InfoElement{
		element: element,
		value:   val,
	}
}

func (f32 *Float32InfoElement) GetInfoElement() *InfoElement {
	return f32.element
}

func (f32 *Float32InfoElement) AddInfoElement(infoElement *InfoElement) {
	f32.element = infoElement
}

func (f32 *Float32InfoElement) GetUnsigned8Value() (uint8, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (f32 *Float32InfoElement) GetUnsigned16Value() (uint16, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (f32 *Float32InfoElement) GetUnsigned32Value() (uint32, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (f32 *Float32InfoElement) GetUnsigned64Value() (uint64, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (f32 *Float32InfoElement) GetSigned8Value() (int8, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (f32 *Float32InfoElement) GetSigned16Value() (int16, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (f32 *Float32InfoElement) GetSigned32Value() (int32, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (f32 *Float32InfoElement) GetSigned64Value() (int64, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (f32 *Float32InfoElement) GetFloat32Value() (float32, error) {
	return f32.value, nil
}

func (f32 *Float32InfoElement) GetFloat64Value() (float64, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (f32 *Float32InfoElement) GetBooleanValue() (bool, error) {
	return false, fmt.Errorf("accessing value of wrong data type")
}

func (f32 *Float32InfoElement) GetMacAddressValue() (net.HardwareAddr, error) {
	return nil, fmt.Errorf("accessing value of wrong data type")
}

func (f32 *Float32InfoElement) GetStringValue() (string, error) {
	return "", fmt.Errorf("accessing value of wrong data type")
}

func (f32 *Float32InfoElement) GetIPAddressValue() (net.IP, error) {
	return nil, fmt.Errorf("accessing value of wrong data type")
}

func (f32 *Float32InfoElement) SetUnsigned8Value(val uint8) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (f32 *Float32InfoElement) SetUnsigned16Value(val uint16) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (f32 *Float32InfoElement) SetUnsigned32Value(val uint32) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (f32 *Float32InfoElement) SetUnsigned64Value(val uint64) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (f32 *Float32InfoElement) SetSigned8Value(val int8) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (f32 *Float32InfoElement) SetSigned16Value(val int16) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (f32 *Float32InfoElement) SetSigned32Value(val int32) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (f32 *Float32InfoElement) SetSigned64Value(val int64) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (f32 *Float32InfoElement) SetFloat32Value(val float32) error {
	f32.value = val
	return nil
}

func (f32 *Float32InfoElement) SetFloat64Value(val float64) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (f32 *Float32InfoElement) SetBooleanValue(val bool) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (f32 *Float32InfoElement) SetMacAddressValue(val net.HardwareAddr) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (f32 *Float32InfoElement) SetStringValue(val string) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (f32 *Float32InfoElement) SetIPAddressValue(val net.IP) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (f32 *Float32InfoElement) IsValueEmpty() bool {
	return f32.value == 0
}

func (f32 *Float32InfoElement) GetLength() int {
	return int(f32.element.Len)
}

func (f32 *Float32InfoElement) ResetValue() {
	f32.value = 0
}

type Float64InfoElement struct {
	value   float64
	element *InfoElement
}

func NewFloat64InfoElement(element *InfoElement, val float64) *Float64InfoElement {
	return &Float64InfoElement{
		element: element,
		value:   val,
	}
}

func (f64 *Float64InfoElement) GetInfoElement() *InfoElement {
	return f64.element
}

func (f64 *Float64InfoElement) AddInfoElement(infoElement *InfoElement) {
	f64.element = infoElement
}

func (f64 *Float64InfoElement) GetUnsigned8Value() (uint8, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (f64 *Float64InfoElement) GetUnsigned16Value() (uint16, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (f64 *Float64InfoElement) GetUnsigned32Value() (uint32, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (f64 *Float64InfoElement) GetUnsigned64Value() (uint64, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (f64 *Float64InfoElement) GetSigned8Value() (int8, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (f64 *Float64InfoElement) GetSigned16Value() (int16, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (f64 *Float64InfoElement) GetSigned32Value() (int32, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (f64 *Float64InfoElement) GetSigned64Value() (int64, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (f64 *Float64InfoElement) GetFloat32Value() (float32, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (f64 *Float64InfoElement) GetFloat64Value() (float64, error) {
	return f64.value, nil
}

func (f64 *Float64InfoElement) GetBooleanValue() (bool, error) {
	return false, fmt.Errorf("accessing value of wrong data type")
}

func (f64 *Float64InfoElement) GetMacAddressValue() (net.HardwareAddr, error) {
	return nil, fmt.Errorf("accessing value of wrong data type")
}

func (f64 *Float64InfoElement) GetStringValue() (string, error) {
	return "", fmt.Errorf("accessing value of wrong data type")
}

func (f64 *Float64InfoElement) GetIPAddressValue() (net.IP, error) {
	return nil, fmt.Errorf("accessing value of wrong data type")
}

func (f64 *Float64InfoElement) SetUnsigned8Value(val uint8) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (f64 *Float64InfoElement) SetUnsigned16Value(val uint16) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (f64 *Float64InfoElement) SetUnsigned32Value(val uint32) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (f64 *Float64InfoElement) SetUnsigned64Value(val uint64) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (f64 *Float64InfoElement) SetSigned8Value(val int8) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (f64 *Float64InfoElement) SetSigned16Value(val int16) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (f64 *Float64InfoElement) SetSigned32Value(val int32) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (f64 *Float64InfoElement) SetSigned64Value(val int64) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (f64 *Float64InfoElement) SetFloat32Value(val float32) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (f64 *Float64InfoElement) SetFloat64Value(val float64) error {
	f64.value = val
	return nil
}

func (f64 *Float64InfoElement) SetBooleanValue(val bool) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (f64 *Float64InfoElement) SetMacAddressValue(val net.HardwareAddr) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (f64 *Float64InfoElement) SetStringValue(val string) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (f64 *Float64InfoElement) SetIPAddressValue(val net.IP) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (f64 *Float64InfoElement) IsValueEmpty() bool {
	return f64.value == 0
}

func (f64 *Float64InfoElement) GetLength() int {
	return int(f64.element.Len)
}

func (f64 *Float64InfoElement) ResetValue() {
	f64.value = 0
}

type BooleanInfoElement struct {
	value   bool
	element *InfoElement
}

func NewBoolInfoElement(element *InfoElement, val bool) *BooleanInfoElement {
	return &BooleanInfoElement{
		element: element,
		value:   val,
	}
}

func (b *BooleanInfoElement) GetInfoElement() *InfoElement {
	return b.element
}

func (b *BooleanInfoElement) AddInfoElement(infoElement *InfoElement) {
	b.element = infoElement
}

func (b *BooleanInfoElement) GetUnsigned8Value() (uint8, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (b *BooleanInfoElement) GetUnsigned16Value() (uint16, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (b *BooleanInfoElement) GetUnsigned32Value() (uint32, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (b *BooleanInfoElement) GetUnsigned64Value() (uint64, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (b *BooleanInfoElement) GetSigned8Value() (int8, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (b *BooleanInfoElement) GetSigned16Value() (int16, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (b *BooleanInfoElement) GetSigned32Value() (int32, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (b *BooleanInfoElement) GetSigned64Value() (int64, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (b *BooleanInfoElement) GetFloat32Value() (float32, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (b *BooleanInfoElement) GetFloat64Value() (float64, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (b *BooleanInfoElement) GetBooleanValue() (bool, error) {
	return b.value, nil
}

func (b *BooleanInfoElement) GetMacAddressValue() (net.HardwareAddr, error) {
	return nil, fmt.Errorf("accessing value of wrong data type")
}

func (b *BooleanInfoElement) GetStringValue() (string, error) {
	return "", fmt.Errorf("accessing value of wrong data type")
}

func (b *BooleanInfoElement) GetIPAddressValue() (net.IP, error) {
	return nil, fmt.Errorf("accessing value of wrong data type")
}

func (b *BooleanInfoElement) SetUnsigned8Value(val uint8) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (b *BooleanInfoElement) SetUnsigned16Value(val uint16) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (b *BooleanInfoElement) SetUnsigned32Value(val uint32) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (b *BooleanInfoElement) SetUnsigned64Value(val uint64) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (b *BooleanInfoElement) SetSigned8Value(val int8) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (b *BooleanInfoElement) SetSigned16Value(val int16) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (b *BooleanInfoElement) SetSigned32Value(val int32) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (b *BooleanInfoElement) SetSigned64Value(val int64) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (b *BooleanInfoElement) SetFloat32Value(val float32) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (b *BooleanInfoElement) SetFloat64Value(val float64) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (b *BooleanInfoElement) SetBooleanValue(val bool) error {
	b.value = val
	return nil
}

func (b *BooleanInfoElement) SetMacAddressValue(val net.HardwareAddr) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (b *BooleanInfoElement) SetStringValue(val string) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (b *BooleanInfoElement) SetIPAddressValue(val net.IP) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (b *BooleanInfoElement) IsValueEmpty() bool {
	return b.value == false
}

func (b *BooleanInfoElement) GetLength() int {
	return int(b.element.Len)
}

func (b *BooleanInfoElement) ResetValue() {
	b.value = false
}

type MacAddressInfoElement struct {
	value   net.HardwareAddr
	element *InfoElement
}

func NewMacAddressInfoElement(element *InfoElement, val net.HardwareAddr) *MacAddressInfoElement {
	return &MacAddressInfoElement{
		element: element,
		value:   val,
	}
}

func (mac *MacAddressInfoElement) GetInfoElement() *InfoElement {
	return mac.element
}

func (mac *MacAddressInfoElement) AddInfoElement(infoElement *InfoElement) {
	mac.element = infoElement
}

func (mac *MacAddressInfoElement) GetUnsigned8Value() (uint8, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (mac *MacAddressInfoElement) GetUnsigned16Value() (uint16, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (mac *MacAddressInfoElement) GetUnsigned32Value() (uint32, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (mac *MacAddressInfoElement) GetUnsigned64Value() (uint64, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (mac *MacAddressInfoElement) GetSigned8Value() (int8, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (mac *MacAddressInfoElement) GetSigned16Value() (int16, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (mac *MacAddressInfoElement) GetSigned32Value() (int32, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (mac *MacAddressInfoElement) GetSigned64Value() (int64, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (mac *MacAddressInfoElement) GetFloat32Value() (float32, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (mac *MacAddressInfoElement) GetFloat64Value() (float64, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (mac *MacAddressInfoElement) GetBooleanValue() (bool, error) {
	return false, fmt.Errorf("accessing value of wrong data type")
}

func (mac *MacAddressInfoElement) GetMacAddressValue() (net.HardwareAddr, error) {
	return mac.value, nil
}

func (mac *MacAddressInfoElement) GetStringValue() (string, error) {
	return "", fmt.Errorf("accessing value of wrong data type")
}

func (mac *MacAddressInfoElement) GetIPAddressValue() (net.IP, error) {
	return nil, fmt.Errorf("accessing value of wrong data type")
}

func (mac *MacAddressInfoElement) SetUnsigned8Value(val uint8) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (mac *MacAddressInfoElement) SetUnsigned16Value(val uint16) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (mac *MacAddressInfoElement) SetUnsigned32Value(val uint32) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (mac *MacAddressInfoElement) SetUnsigned64Value(val uint64) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (mac *MacAddressInfoElement) SetSigned8Value(val int8) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (mac *MacAddressInfoElement) SetSigned16Value(val int16) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (mac *MacAddressInfoElement) SetSigned32Value(val int32) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (mac *MacAddressInfoElement) SetSigned64Value(val int64) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (mac *MacAddressInfoElement) SetFloat32Value(val float32) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (mac *MacAddressInfoElement) SetFloat64Value(val float64) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (mac *MacAddressInfoElement) SetBooleanValue(val bool) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (mac *MacAddressInfoElement) SetMacAddressValue(val net.HardwareAddr) error {
	mac.value = val
	return nil
}

func (mac *MacAddressInfoElement) SetStringValue(val string) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (mac *MacAddressInfoElement) SetIPAddressValue(val net.IP) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (mac *MacAddressInfoElement) IsValueEmpty() bool {
	return mac.value == nil
}

func (mac *MacAddressInfoElement) GetLength() int {
	return int(mac.element.Len)
}

func (mac *MacAddressInfoElement) ResetValue() {
	mac.value = nil
}

type StringInfoElement struct {
	element *InfoElement
	value   string
	length  int
}

func NewStringInfoElement(element *InfoElement, val string) *StringInfoElement {
	return &StringInfoElement{
		element: element,
		value:   val,
		length:  len(val),
	}
}

func (s *StringInfoElement) GetInfoElement() *InfoElement {
	return s.element
}

func (s *StringInfoElement) AddInfoElement(infoElement *InfoElement) {
	s.element = infoElement
}

func (s *StringInfoElement) GetUnsigned8Value() (uint8, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (s *StringInfoElement) GetUnsigned16Value() (uint16, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (s *StringInfoElement) GetUnsigned32Value() (uint32, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (s *StringInfoElement) GetUnsigned64Value() (uint64, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (s *StringInfoElement) GetSigned8Value() (int8, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (s *StringInfoElement) GetSigned16Value() (int16, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (s *StringInfoElement) GetSigned32Value() (int32, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (s *StringInfoElement) GetSigned64Value() (int64, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (s *StringInfoElement) GetFloat32Value() (float32, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (s *StringInfoElement) GetFloat64Value() (float64, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (s *StringInfoElement) GetBooleanValue() (bool, error) {
	return false, fmt.Errorf("accessing value of wrong data type")
}

func (s *StringInfoElement) GetMacAddressValue() (net.HardwareAddr, error) {
	return nil, fmt.Errorf("accessing value of wrong data type")
}

func (s *StringInfoElement) GetStringValue() (string, error) {
	return s.value, nil
}

func (s *StringInfoElement) GetIPAddressValue() (net.IP, error) {
	return nil, fmt.Errorf("accessing value of wrong data type")
}

func (s *StringInfoElement) SetValue(value string) {
	s.value = value
}

func (s *StringInfoElement) GetLength() int {
	if len(s.value) < 255 {
		return len(s.value) + 1
	} else {
		return len(s.value) + 3
	}
}

func (s *StringInfoElement) SetUnsigned8Value(val uint8) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (s *StringInfoElement) SetUnsigned16Value(val uint16) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (s *StringInfoElement) SetUnsigned32Value(val uint32) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (s *StringInfoElement) SetUnsigned64Value(val uint64) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (s *StringInfoElement) SetSigned8Value(val int8) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (s *StringInfoElement) SetSigned16Value(val int16) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (s *StringInfoElement) SetSigned32Value(val int32) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (s *StringInfoElement) SetSigned64Value(val int64) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (s *StringInfoElement) SetFloat32Value(val float32) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (s *StringInfoElement) SetFloat64Value(val float64) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (s *StringInfoElement) SetBooleanValue(val bool) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (s *StringInfoElement) SetMacAddressValue(val net.HardwareAddr) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (s *StringInfoElement) SetStringValue(val string) error {
	s.value = val
	return nil
}

func (s *StringInfoElement) SetIPAddressValue(val net.IP) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (s *StringInfoElement) IsValueEmpty() bool {
	return s.value == ""
}

func (s *StringInfoElement) ResetValue() {
	s.value = ""
}

type DateTimeSecondsInfoElement struct {
	value   uint32
	element *InfoElement
}

func NewDateTimeSecondsInfoElement(element *InfoElement, val uint32) *DateTimeSecondsInfoElement {
	return &DateTimeSecondsInfoElement{
		element: element,
		value:   val,
	}
}

func (dsec *DateTimeSecondsInfoElement) GetInfoElement() *InfoElement {
	return dsec.element
}

func (dsec *DateTimeSecondsInfoElement) AddInfoElement(infoElement *InfoElement) {
	dsec.element = infoElement
}

func (dsec *DateTimeSecondsInfoElement) GetUnsigned8Value() (uint8, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (dsec *DateTimeSecondsInfoElement) GetUnsigned16Value() (uint16, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (dsec *DateTimeSecondsInfoElement) GetUnsigned32Value() (uint32, error) {
	return dsec.value, nil
}

func (dsec *DateTimeSecondsInfoElement) GetUnsigned64Value() (uint64, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (dsec *DateTimeSecondsInfoElement) GetSigned8Value() (int8, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (dsec *DateTimeSecondsInfoElement) GetSigned16Value() (int16, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (dsec *DateTimeSecondsInfoElement) GetSigned32Value() (int32, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (dsec *DateTimeSecondsInfoElement) GetSigned64Value() (int64, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (dsec *DateTimeSecondsInfoElement) GetFloat32Value() (float32, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (dsec *DateTimeSecondsInfoElement) GetFloat64Value() (float64, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (dsec *DateTimeSecondsInfoElement) GetBooleanValue() (bool, error) {
	return false, fmt.Errorf("accessing value of wrong data type")
}

func (dsec *DateTimeSecondsInfoElement) GetMacAddressValue() (net.HardwareAddr, error) {
	return nil, fmt.Errorf("accessing value of wrong data type")
}

func (dsec *DateTimeSecondsInfoElement) GetStringValue() (string, error) {
	return "", fmt.Errorf("accessing value of wrong data type")
}

func (dsec *DateTimeSecondsInfoElement) GetIPAddressValue() (net.IP, error) {
	return nil, fmt.Errorf("accessing value of wrong data type")
}

func (dsec *DateTimeSecondsInfoElement) SetUnsigned8Value(val uint8) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (dsec *DateTimeSecondsInfoElement) SetUnsigned16Value(val uint16) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (dsec *DateTimeSecondsInfoElement) SetUnsigned32Value(val uint32) error {
	dsec.value = val
	return nil
}

func (dsec *DateTimeSecondsInfoElement) SetUnsigned64Value(val uint64) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (dsec *DateTimeSecondsInfoElement) SetSigned8Value(val int8) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (dsec *DateTimeSecondsInfoElement) SetSigned16Value(val int16) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (dsec *DateTimeSecondsInfoElement) SetSigned32Value(val int32) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (dsec *DateTimeSecondsInfoElement) SetSigned64Value(val int64) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (dsec *DateTimeSecondsInfoElement) SetFloat32Value(val float32) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (dsec *DateTimeSecondsInfoElement) SetFloat64Value(val float64) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (dsec *DateTimeSecondsInfoElement) SetBooleanValue(val bool) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (dsec *DateTimeSecondsInfoElement) SetMacAddressValue(val net.HardwareAddr) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (dsec *DateTimeSecondsInfoElement) SetStringValue(val string) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (dsec *DateTimeSecondsInfoElement) SetIPAddressValue(val net.IP) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (dsec *DateTimeSecondsInfoElement) IsValueEmpty() bool {
	return dsec.value == 0
}

func (dsec *DateTimeSecondsInfoElement) GetLength() int {
	return int(dsec.element.Len)
}

func (dsec *DateTimeSecondsInfoElement) ResetValue() {
	dsec.value = 0
}

type DateTimeMillisecondsInfoElement struct {
	value   uint64
	element *InfoElement
}

func NewDateTimeMillisecondsInfoElement(element *InfoElement, val uint64) *DateTimeMillisecondsInfoElement {
	return &DateTimeMillisecondsInfoElement{
		element: element,
		value:   val,
	}
}

func (dmsec *DateTimeMillisecondsInfoElement) GetInfoElement() *InfoElement {
	return dmsec.element
}

func (dmsec *DateTimeMillisecondsInfoElement) AddInfoElement(infoElement *InfoElement) {
	dmsec.element = infoElement
}

func (dmsec *DateTimeMillisecondsInfoElement) GetUnsigned8Value() (uint8, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (dmsec *DateTimeMillisecondsInfoElement) GetUnsigned16Value() (uint16, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (dmsec *DateTimeMillisecondsInfoElement) GetUnsigned32Value() (uint32, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (dmsec *DateTimeMillisecondsInfoElement) GetUnsigned64Value() (uint64, error) {
	return dmsec.value, nil
}

func (dmsec *DateTimeMillisecondsInfoElement) GetSigned8Value() (int8, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (dmsec *DateTimeMillisecondsInfoElement) GetSigned16Value() (int16, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (dmsec *DateTimeMillisecondsInfoElement) GetSigned32Value() (int32, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (dmsec *DateTimeMillisecondsInfoElement) GetSigned64Value() (int64, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (dmsec *DateTimeMillisecondsInfoElement) GetFloat32Value() (float32, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (dmsec *DateTimeMillisecondsInfoElement) GetFloat64Value() (float64, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (dmsec *DateTimeMillisecondsInfoElement) GetBooleanValue() (bool, error) {
	return false, fmt.Errorf("accessing value of wrong data type")
}

func (dmsec *DateTimeMillisecondsInfoElement) GetMacAddressValue() (net.HardwareAddr, error) {
	return nil, fmt.Errorf("accessing value of wrong data type")
}

func (dmsec *DateTimeMillisecondsInfoElement) GetStringValue() (string, error) {
	return "", fmt.Errorf("accessing value of wrong data type")
}

func (dmsec *DateTimeMillisecondsInfoElement) GetIPAddressValue() (net.IP, error) {
	return nil, fmt.Errorf("accessing value of wrong data type")
}

func (dmsec *DateTimeMillisecondsInfoElement) SetUnsigned8Value(val uint8) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (dmsec *DateTimeMillisecondsInfoElement) SetUnsigned16Value(val uint16) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (dmsec *DateTimeMillisecondsInfoElement) SetUnsigned32Value(val uint32) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (dmsec *DateTimeMillisecondsInfoElement) SetUnsigned64Value(val uint64) error {
	dmsec.value = val
	return nil
}

func (dmsec *DateTimeMillisecondsInfoElement) SetSigned8Value(val int8) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (dmsec *DateTimeMillisecondsInfoElement) SetSigned16Value(val int16) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (dmsec *DateTimeMillisecondsInfoElement) SetSigned32Value(val int32) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (dmsec *DateTimeMillisecondsInfoElement) SetSigned64Value(val int64) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (dmsec *DateTimeMillisecondsInfoElement) SetFloat32Value(val float32) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (dmsec *DateTimeMillisecondsInfoElement) SetFloat64Value(val float64) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (dmsec *DateTimeMillisecondsInfoElement) SetBooleanValue(val bool) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (dmsec *DateTimeMillisecondsInfoElement) SetMacAddressValue(val net.HardwareAddr) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (dmsec *DateTimeMillisecondsInfoElement) SetStringValue(val string) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (dmsec *DateTimeMillisecondsInfoElement) SetIPAddressValue(val net.IP) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (dmsec *DateTimeMillisecondsInfoElement) IsValueEmpty() bool {
	return dmsec.value == 0
}

func (dmsec *DateTimeMillisecondsInfoElement) GetLength() int {
	return int(dmsec.element.Len)
}

func (dmsec *DateTimeMillisecondsInfoElement) ResetValue() {
	dmsec.value = 0
}

type IPAddressInfoElement struct {
	element *InfoElement
	value   net.IP
}

func NewIPAddressInfoElement(element *InfoElement, val net.IP) *IPAddressInfoElement {
	return &IPAddressInfoElement{
		element: element,
		value:   val,
	}
}

func (ip *IPAddressInfoElement) GetInfoElement() *InfoElement {
	return ip.element
}

func (ip *IPAddressInfoElement) AddInfoElement(infoElement *InfoElement) {
	ip.element = infoElement
}

func (ip *IPAddressInfoElement) GetUnsigned8Value() (uint8, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (ip *IPAddressInfoElement) GetUnsigned16Value() (uint16, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (ip *IPAddressInfoElement) GetUnsigned32Value() (uint32, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (ip *IPAddressInfoElement) GetUnsigned64Value() (uint64, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (ip *IPAddressInfoElement) GetSigned8Value() (int8, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (ip *IPAddressInfoElement) GetSigned16Value() (int16, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (ip *IPAddressInfoElement) GetSigned32Value() (int32, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (ip *IPAddressInfoElement) GetSigned64Value() (int64, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (ip *IPAddressInfoElement) GetFloat32Value() (float32, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (ip *IPAddressInfoElement) GetFloat64Value() (float64, error) {
	return 0, fmt.Errorf("accessing value of wrong data type")
}

func (ip *IPAddressInfoElement) GetBooleanValue() (bool, error) {
	return false, fmt.Errorf("accessing value of wrong data type")
}

func (ip *IPAddressInfoElement) GetMacAddressValue() (net.HardwareAddr, error) {
	return nil, fmt.Errorf("accessing value of wrong data type")
}

func (ip *IPAddressInfoElement) GetStringValue() (string, error) {
	return "", fmt.Errorf("accessing value of wrong data type")
}

func (ip *IPAddressInfoElement) GetIPAddressValue() (net.IP, error) {
	return ip.value, nil
}

func (ip *IPAddressInfoElement) SetUnsigned8Value(val uint8) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (ip *IPAddressInfoElement) SetUnsigned16Value(val uint16) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (ip *IPAddressInfoElement) SetUnsigned32Value(val uint32) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (ip *IPAddressInfoElement) SetUnsigned64Value(val uint64) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (ip *IPAddressInfoElement) SetSigned8Value(val int8) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (ip *IPAddressInfoElement) SetSigned16Value(val int16) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (ip *IPAddressInfoElement) SetSigned32Value(val int32) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (ip *IPAddressInfoElement) SetSigned64Value(val int64) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (ip *IPAddressInfoElement) SetFloat32Value(val float32) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (ip *IPAddressInfoElement) SetFloat64Value(val float64) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (ip *IPAddressInfoElement) SetBooleanValue(val bool) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (ip *IPAddressInfoElement) SetMacAddressValue(val net.HardwareAddr) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (ip *IPAddressInfoElement) SetStringValue(val string) error {
	return fmt.Errorf("setting value with wrong data type: %T", val)
}

func (ip *IPAddressInfoElement) SetIPAddressValue(val net.IP) error {
	ip.value = val
	return nil
}

func (ip *IPAddressInfoElement) IsValueEmpty() bool {
	return ip.value == nil
}

func (ip *IPAddressInfoElement) GetLength() int {
	return int(ip.element.Len)
}

func (ip *IPAddressInfoElement) ResetValue() {
	ip.value = nil
}
