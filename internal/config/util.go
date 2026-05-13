package config

import (
	"bytes"
	"strings"
)

// bytesReader wraps a byte slice as an io.Reader. Tiny helper kept
// out of config.go to keep that file focused on the schema.
func bytesReader(b []byte) *bytes.Reader { return bytes.NewReader(b) }

// joinErrs concatenates validation error strings into a single
// human-readable message. We don't use errors.Join because Go 1.20
// support is still our floor; switch to errors.Join when we move
// up to 1.21+.
func joinErrs(errs []string) string {
	return strings.Join(errs, "; ")
}
