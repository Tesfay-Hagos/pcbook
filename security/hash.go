package security

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"reflect"
)

type hashs struct {
}

func NewHash() *hashs {
	return &hashs{}
}
func (h *hashs) HashStruct(obj interface{}) (string, error) {
	// Convert the struct object to bytes
	objBytes, err := h.structToBytes(obj)
	if err != nil {
		return "", err
	}

	// Calculate the hash value using SHA-256
	hash := sha256.Sum256(objBytes)

	// Convert the hash value to a hexadecimal string
	hashString := hex.EncodeToString(hash[:])
	return hashString, nil
}
func (h *hashs) AssertHash(hash string, object interface{}) bool {
	hashnew, err := h.HashStruct(object)

	if err != nil {
		return false
	}
	if hashnew != hash {
		return false
	}
	return true
}
func (h *hashs) structToBytes(obj interface{}) ([]byte, error) {
	// Use reflection to obtain the underlying bytes of the struct object
	objType := reflect.TypeOf(obj)
	objValue := reflect.ValueOf(obj)

	// Ensure that the input is a struct
	if objType.Kind() != reflect.Struct {
		return nil, fmt.Errorf("input is not a struct")
	}

	// Initialize a byte slice to store the struct bytes
	var objBytes []byte

	// Iterate over the struct fields
	for i := 0; i < objType.NumField(); i++ {
		field := objValue.Field(i)

		// Obtain the field value as bytes
		fieldBytes, err := h.valueToBytes(field)
		if err != nil {
			return nil, err
		}

		// Append the field bytes to the struct bytes
		objBytes = append(objBytes, fieldBytes...)
	}

	return objBytes, nil
}

func (h *hashs) valueToBytes(value reflect.Value) ([]byte, error) {
	// Check the type of the value and obtain its bytes accordingly
	switch value.Kind() {
	case reflect.Bool:
		if value.Bool() {
			return []byte{1}, nil
		} else {
			return []byte{0}, nil
		}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return []byte(fmt.Sprintf("%d", value.Int())), nil
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return []byte(fmt.Sprintf("%d", value.Uint())), nil
	case reflect.Float32, reflect.Float64:
		return []byte(fmt.Sprintf("%f", value.Float())), nil
	case reflect.String:
		return []byte(value.String()), nil
	case reflect.Struct:
		return h.structToBytes(value.Interface())
	default:
		return nil, fmt.Errorf("unsupported type: %s", value.Kind())
	}
}
