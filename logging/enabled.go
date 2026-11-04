//go:build !release

package logging

// logsEnabled is true in development builds. Release builds keep no logs.
const logsEnabled = true
