//go:build race

package api

// The race detector needs room for shadow memory outside the Go heap.
const schemaWorkerDataLimit = 2 << 30
