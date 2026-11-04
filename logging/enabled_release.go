//go:build release

package logging

// logsEnabled is false in release builds (`-tags release`, which `make build`
// and the Dockerfile pass). The node's log lines hold client addresses, device
// key tags and who links with whom, and a release keeps none of that.
const logsEnabled = false
