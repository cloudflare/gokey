// Code generated by "stringer -type KeyType"; DO NOT EDIT.

package gokey

import "strconv"

func _() {
	// An "invalid array index" compiler error signifies that the constant values have changed.
	// Re-run the stringer command to generate them again.
	var x [1]struct{}
	_ = x[EC256-0]
	_ = x[EC384-1]
	_ = x[EC521-2]
	_ = x[RSA2048-3]
	_ = x[RSA4096-4]
	_ = x[X25519-5]
	_ = x[ED25519-6]
}

const _KeyType_name = "EC256EC384EC521RSA2048RSA4096X25519ED25519"

var _KeyType_index = [...]uint8{0, 5, 10, 15, 22, 29, 35, 42}

func (i KeyType) String() string {
	if i < 0 || i >= KeyType(len(_KeyType_index)-1) {
		return "KeyType(" + strconv.FormatInt(int64(i), 10) + ")"
	}
	return _KeyType_name[_KeyType_index[i]:_KeyType_index[i+1]]
}
