//go:build !darwin

package main

import (
	"context"
	"fmt"
)

func snapshotPortIdentities(context.Context) (map[int]portIdentity, error) {
	return nil, fmt.Errorf("process identity requires macOS")
}

func readPortIdentity(context.Context, int) (portIdentity, error) {
	return portIdentity{}, fmt.Errorf("process identity requires macOS")
}

func readPortPath(context.Context, int) (string, error) {
	return "", fmt.Errorf("process path requires macOS")
}
