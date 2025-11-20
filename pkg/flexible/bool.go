package flexible

import (
	"encoding/json"
	"strconv"
)

type Bool bool

func (b *Bool) UnmarshalJSON(data []byte) error {
	var v any
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}

	*b = Bool(anyToBool(v))

	return nil
}

func (b Bool) MarshalJSON() ([]byte, error) {
	return json.Marshal(bool(b))
}

func (b *Bool) Bool() bool {
	if b == nil {
		return false
	}

	return bool(*b)
}

func anyToBool(v any) bool {
	switch val := v.(type) {
	case bool:
		return val
	case string:
		b, err := strconv.ParseBool(val)
		if err != nil {
			return val == "yes" || val == "YES" || val == "Yes" ||
				val == "on" || val == "ON" || val == "On"
		}

		return b
	case int:
		return val != 0
	case int8:
		return val != 0
	case int16:
		return val != 0
	case int32:
		return val != 0
	case int64:
		return val != 0
	case uint:
		return val != 0
	case uint8:
		return val != 0
	case uint16:
		return val != 0
	case uint32:
		return val != 0
	case uint64:
		return val != 0
	case float32:
		return val != 0.0
	case float64:
		return val != 0.0
	default:
		return false
	}
}
