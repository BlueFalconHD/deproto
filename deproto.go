package deproto

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"strconv"
	"strings"
	"unicode"
)

// Wire type constants as per protobuf specification.
const (
	WireVarint     = 0
	WireFixed64    = 1
	WireBytes      = 2
	WireStartGroup = 3
	WireEndGroup   = 4
	WireFixed32    = 5
)

// Field interface represents a generic protobuf field.
type Field interface {
	// Render returns a string representation of the field with the given indentation level.
	Render(indentLevel int) string
}

// FieldBase holds common attributes for all fields.
type FieldBase struct {
	ID       int // Field number
	WireType int // Wire type
}

// Returns a string representation of the wire type.
func wireTypeString(wireType int) string {
	switch wireType {
	case WireVarint:
		return "Varint"
	case WireFixed64:
		return "Fixed64"
	case WireBytes:
		return "Length-delimited"
	case WireFixed32:
		return "Fixed32"
	default:
		return fmt.Sprintf("Unknown(%d)", wireType)
	}
}

// VarintField represents a field with varint wire type.
type VarintField struct {
	FieldBase
	Value uint64 // The decoded varint value
}

// Render returns a string representation of the VarintField.
func (v *VarintField) Render(indentLevel int) string {
	indent := strings.Repeat("    ", indentLevel)
	return fmt.Sprintf("%s[%d %s]: %d (0x%x)\n", indent, v.ID, wireTypeString(v.WireType), v.Value, v.Value)
}

// Fixed64Field represents a field with fixed64 wire type.
type Fixed64Field struct {
	FieldBase
	Value uint64 // The 64-bit value
}

// Render returns a string representation of the Fixed64Field.
func (f *Fixed64Field) Render(indentLevel int) string {
	indent := strings.Repeat("    ", indentLevel)
	floatValue := math.Float64frombits(f.Value)
	return fmt.Sprintf("%s[%d %s]: %d (0x%x) (%f)\n", indent, f.ID, wireTypeString(f.WireType), f.Value, f.Value, floatValue)
}

// Fixed32Field represents a field with fixed32 wire type.
type Fixed32Field struct {
	FieldBase
	Value uint32 // The 32-bit value
}

// Render returns a string representation of the Fixed32Field.
func (f *Fixed32Field) Render(indentLevel int) string {
	indent := strings.Repeat("    ", indentLevel)
	floatValue := math.Float32frombits(f.Value)
	return fmt.Sprintf("%s[%d %s]: %d (0x%x) (%f)\n", indent, f.ID, wireTypeString(f.WireType), f.Value, f.Value, floatValue)
}

// LengthDelimitedField represents a field with length-delimited wire type.
type LengthDelimitedField struct {
	FieldBase
	Data        []byte  // The raw data
	SubFields   []Field // Nested fields if any
	IsString    bool    // Indicates if data is a printable string
	StringValue string  // The string value if data is printable
}

// Render returns a string representation of the LengthDelimitedField.
func (l *LengthDelimitedField) Render(indentLevel int) string {
	indent := strings.Repeat("    ", indentLevel)
	var b strings.Builder
	fmt.Fprintf(&b, "%s[%d %s]: (%d bytes)", indent, l.ID, wireTypeString(l.WireType), len(l.Data))

	if l.IsString {
		fmt.Fprintf(&b, " %s\n", strconv.Quote(l.StringValue))
	} else if len(l.SubFields) > 0 {
		fmt.Fprintf(&b, "\n")
		for _, sf := range l.SubFields {
			b.WriteString(sf.Render(indentLevel + 1))
		}
	} else {
		fmt.Fprintf(&b, " [hex] %s\n", hex.EncodeToString(l.Data))
	}
	return b.String()
}

// DecodeField decodes a single field from the given data.
func DecodeField(data []byte) (Field, int, error) {
	var fieldKey uint64
	var n int

	fieldKey, n = binary.Uvarint(data)
	if n <= 0 {
		return nil, 0, fmt.Errorf("failed to read field key varint")
	}

	fieldNumber := int(fieldKey >> 3)
	wireType := int(fieldKey & 0x7)

	fieldBase := FieldBase{
		ID:       fieldNumber,
		WireType: wireType,
	}

	switch wireType {
	case WireVarint:
		value, m := binary.Uvarint(data[n:])
		if m <= 0 {
			return nil, 0, fmt.Errorf("failed to read varint value")
		}
		totalBytesRead := n + m
		field := &VarintField{
			FieldBase: fieldBase,
			Value:     value,
		}
		return field, totalBytesRead, nil

	case WireFixed64:
		if len(data) < n+8 {
			return nil, 0, fmt.Errorf("not enough data for fixed64")
		}
		value := binary.LittleEndian.Uint64(data[n : n+8])
		totalBytesRead := n + 8
		field := &Fixed64Field{
			FieldBase: fieldBase,
			Value:     value,
		}
		return field, totalBytesRead, nil

	case WireBytes:
		length, m := binary.Uvarint(data[n:])
		if m <= 0 {
			return nil, 0, fmt.Errorf("failed to read length of length-delimited field")
		}
		totalBytesRead := n + m + int(length)
		if len(data) < totalBytesRead {
			return nil, 0, fmt.Errorf("not enough data for length-delimited field")
		}
		bytesValue := data[n+m : totalBytesRead]
		field := &LengthDelimitedField{
			FieldBase: fieldBase,
			Data:      bytesValue,
		}
		// Attempt to parse as nested fields
		subFields, err := DecodeFields(bytesValue)
		if err == nil && len(subFields) > 0 {
			field.SubFields = subFields
		} else if isPrintableString(bytesValue) {
			field.IsString = true
			field.StringValue = string(bytesValue)
		}
		return field, totalBytesRead, nil

	case WireFixed32:
		if len(data) < n+4 {
			return nil, 0, fmt.Errorf("not enough data for fixed32")
		}
		value := binary.LittleEndian.Uint32(data[n : n+4])
		totalBytesRead := n + 4
		field := &Fixed32Field{
			FieldBase: fieldBase,
			Value:     value,
		}
		return field, totalBytesRead, nil

	default:
		return nil, 0, fmt.Errorf("unknown wire type %d", wireType)
	}
}

// DecodeFields decodes all fields from the given data.
func DecodeFields(data []byte) ([]Field, error) {
	var fields []Field
	pos := 0
	for pos < len(data) {
		field, n, err := DecodeField(data[pos:])
		if err != nil {
			return fields, err
		}
		fields = append(fields, field)
		pos += n
	}
	return fields, nil
}

// isPrintableString checks if the data is a printable UTF-8 string.
func isPrintableString(data []byte) bool {
	str := string(data)
	for _, r := range str {
		if !unicode.IsPrint(r) && !unicode.IsSpace(r) {
			return false
		}
	}
	return true
}
