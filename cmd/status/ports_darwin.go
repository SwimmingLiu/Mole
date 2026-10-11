//go:build darwin

package main

import (
	"context"
	"fmt"

	"github.com/shirou/gopsutil/v4/process"
	"golang.org/x/sys/unix"
)

func portIdentityFromNative(proc unix.ExternProc) portIdentity {
	end := 0
	for end < len(proc.P_comm) && proc.P_comm[end] != 0 {
		end++
	}
	name := make([]byte, end)
	for i := range name {
		name[i] = byte(proc.P_comm[i])
	}
	return portIdentity{proc.P_starttime.Sec, int64(proc.P_starttime.Usec), string(name)}
}

func snapshotPortIdentities(ctx context.Context) (map[int]portIdentity, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	processes, err := unix.SysctlKinfoProcSlice("kern.proc.all")
	if err != nil {
		return nil, err
	}
	identities := make(map[int]portIdentity, len(processes))
	for _, proc := range processes {
		identities[int(proc.Proc.P_pid)] = portIdentityFromNative(proc.Proc)
	}
	return identities, ctx.Err()
}

func readPortIdentity(ctx context.Context, pid int) (portIdentity, error) {
	if err := ctx.Err(); err != nil {
		return portIdentity{}, err
	}
	proc, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil {
		return portIdentity{}, err
	}
	if int(proc.Proc.P_pid) != pid || proc.Proc.P_starttime.Sec <= 0 {
		return portIdentity{}, fmt.Errorf("process identity unavailable")
	}
	return portIdentityFromNative(proc.Proc), ctx.Err()
}

func readPortPath(ctx context.Context, pid int) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	// Exe uses native proc_pidpath on macOS, without reading command arguments
	// or starting another lsof process for each listener.
	proc := &process.Process{Pid: int32(pid)}
	path, err := proc.ExeWithContext(ctx)
	if ctx.Err() != nil {
		return "", ctx.Err()
	}
	return path, err
}
