package config

import _ "embed"

// embeddedResponseConfigJSON is the compiled-in copy of ransomware_extensions.json.
//
// It is the single source of truth for the ransomware extension list and response
// defaults, and is used as a fallback when the on-disk config is unreadable so detection
// behavior never silently depends on the binary's working directory.
//
//go:embed ransomware_extensions.json
var embeddedResponseConfigJSON []byte
