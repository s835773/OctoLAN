package store

import (
	"bytes"
	"encoding/json"
)

func jsonMarshal(v any) ([]byte, error) { return json.Marshal(v) }

func contains(b []byte, s string) bool { return bytes.Contains(b, []byte(s)) }
