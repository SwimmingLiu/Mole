//go:build darwin

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestPortListenerChild(t *testing.T) {
	network := os.Getenv("MOLE_PORT_LISTENER_NETWORK")
	if network == "" {
		t.Skip("controlled listener helper")
	}
	listener, err := net.Listen(network, os.Getenv("MOLE_PORT_LISTENER_ADDRESS"))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	fmt.Fprintln(os.Stdout, listener.Addr().String())
	time.Sleep(30 * time.Second)
}

func startPortListener(t *testing.T, network, address string) (int, int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestPortListenerChild$")
	cmd.Env = append(os.Environ(), "MOLE_PORT_LISTENER_NETWORK="+network, "MOLE_PORT_LISTENER_ADDRESS="+address, "MOLE_TEST_NO_AUTH=1")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() { cancel(); _ = cmd.Wait() })
	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil {
		t.Fatalf("listener startup: %v %s", err, &stderr)
	}
	_, number, err := net.SplitHostPort(strings.TrimSpace(line))
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(number)
	if err != nil {
		t.Fatal(err)
	}
	return cmd.Process.Pid, port
}

func TestPortQueryLiveIPv4IPv6AndExecutable(t *testing.T) {
	pid4, port := startPortListener(t, "tcp4", "127.0.0.1:0")
	pid6, _ := startPortListener(t, "tcp6", "[::1]:"+strconv.Itoa(port))
	ctx, cancel := context.WithTimeout(context.Background(), portQueryTimeout)
	defer cancel()
	result := collectPortQuery(ctx, port, portDependencies{scanPort, snapshotPortIdentities, readPortIdentity, readPortPath})
	if result.Error != nil {
		t.Fatalf("live query: %+v", result)
	}
	want := map[int]string{pid4: "IPv4", pid6: "IPv6"}
	for _, match := range result.Matches {
		if family, ok := want[match.PID]; ok {
			if match.Family != family || match.Port != port || match.Path == nil {
				t.Fatalf("missing live family/path: %+v", match)
			}
			actual, _ := os.Stat(*match.Path)
			expected, _ := os.Stat(os.Args[0])
			if actual == nil || expected == nil || !os.SameFile(actual, expected) {
				t.Fatalf("listener path is not its executable: %+v", match)
			}
			delete(want, match.PID)
		}
	}
	if len(want) != 0 {
		t.Fatalf("missing listeners %v from %+v", want, result)
	}
}

func TestPortQueryIgnoresClientConnectedToRemotePort(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	client, err := net.Dial("tcp4", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	port := listener.Addr().(*net.TCPAddr).Port
	ctx, cancel := context.WithTimeout(context.Background(), portQueryTimeout)
	defer cancel()
	out, diagnostics, err := scanPort(ctx, port)
	if err != nil || len(diagnostics) != 0 {
		t.Fatalf("scan: %v %q", err, diagnostics)
	}
	if bytes.Contains(out, []byte("ESTABLISHED")) || bytes.Contains(out, []byte("->")) {
		t.Fatalf("scan included client/established connection: %q", out)
	}
	matches, err := parsePortRecords(out, port)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, match := range matches {
		if match.PID == os.Getpid() {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("wanted one listener, not its connected sockets: %+v", matches)
	}
}

func TestPortCLIChild(t *testing.T) {
	port := os.Getenv("MOLE_PORT_CLI_TEST")
	if port == "" {
		t.Skip("CLI helper")
	}
	// A port query must never construct health collectors or read preferences.
	collectProcessesFunc = func() (processSample, error) { panic("health collector ran during port lookup") }
	os.Args = []string{"status", "--port", port, "--json"}
	main()
}

func TestPortCLIDispatchHasIndependentJSON(t *testing.T) {
	pid, port := startPortListener(t, "tcp4", "127.0.0.1:0")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestPortCLIChild$")
	cmd.Env = append(os.Environ(), "MOLE_PORT_CLI_TEST="+strconv.Itoa(port), "HOME="+t.TempDir(), "MOLE_TEST_NO_AUTH=1")
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("CLI error: %v %s", err, &stderr)
	}
	var result portResult
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("not a query JSON result: %v %s", err, &stdout)
	}
	found := false
	for _, match := range result.Matches {
		found = found || match.PID == pid
	}
	if !found || result.Query.Port != port || result.Error != nil || bytes.Contains(stdout.Bytes(), []byte("top_processes")) {
		t.Fatalf("wrong query contract: %+v", result)
	}
}

func TestPortCommandBoundsOutputAndInheritedPipes(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, _, err := runPortCommand(ctx, "/bin/sh", "-c", "yes listener")
	if err == nil {
		t.Fatal("unbounded producer returned success")
	}
	ctx2, cancel2 := context.WithTimeout(context.Background(), time.Second)
	defer cancel2()
	started := time.Now()
	_, _, err = runPortCommand(ctx2, "/bin/sh", "-c", "sleep 30 & exit 0")
	if !errors.Is(err, exec.ErrWaitDelay) || time.Since(started) > 500*time.Millisecond {
		t.Fatalf("inherited pipe did not terminate: %v %s", err, time.Since(started))
	}
}
