package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func listenerRecord(pid, name, family, endpoint string) []byte {
	return []byte("p" + pid + "\x00c" + name + "\x00\nf9\x00t" + family + "\x00PTCP\x00n" + endpoint + "\x00TST=LISTEN\x00\n")
}

func TestPortArgumentValidation(t *testing.T) {
	for _, args := range [][]string{
		{"--port", ""}, {"--port", "0"}, {"--port", "65536"}, {"--port", "-1"},
		{"--port", "+80"}, {"--port", "80 "}, {"--port", "８０"}, {"--port", "abc"},
		{"--port", "80", "--watch"}, {"--port", "80", "--watch=false"},
		{"--port", "80", "--interval", "1s"}, {"--port", "80", "--proc-cpu-alerts=false"},
		{"--port", "80", "extra"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			resetFlags(t)
			var stdout, stderr bytes.Buffer
			code, keepGoing := parseArgs(args, &stdout, &stderr)
			if code != 1 || keepGoing || stdout.Len() != 0 || !strings.Contains(stderr.String(), "mo status --help") {
				t.Fatalf("invalid query: code=%d keep=%v stdout=%q stderr=%q", code, keepGoing, &stdout, &stderr)
			}
		})
	}
	for _, raw := range []string{"1", "8080", "65535", "00080"} {
		t.Run(raw, func(t *testing.T) {
			resetFlags(t)
			var stdout, stderr bytes.Buffer
			if code, ok := parseArgs([]string{"--port", raw, "--json"}, &stdout, &stderr); code != 0 || !ok {
				t.Fatalf("valid port rejected: %s", &stderr)
			}
		})
	}
}

func TestPortRecordsMultipleFamiliesAndDescriptors(t *testing.T) {
	raw := listenerRecord("20", "worker", "IPv6", "[::1]:8080")
	raw = append(raw, listenerRecord("10", "ssh\n\t\x1b[2J", "IPv4", "127.0.0.1:8080")...)
	raw = append(raw, listenerRecord("10", "ssh\n\t\x1b[2J", "IPv4", "127.0.0.1:8080")...)
	raw = append(raw, listenerRecord("30", "other-port", "IPv4", "*:8081")...)
	matches, err := parsePortRecords(raw, 8080)
	if err != nil || len(matches) != 2 || matches[0].PID != 10 || matches[1].Family != "IPv6" || matches[1].Address != "::1" {
		t.Fatalf("matches=%+v err=%v", matches, err)
	}
	if matches[0].Name != "ssh\n\t\x1b[2J" {
		t.Fatal("NUL fields did not preserve the name bytes")
	}
}

func TestPortRecordsRefuseIncompleteOrUnexpectedData(t *testing.T) {
	good := listenerRecord("10", "worker", "IPv4", "*:8080")
	cases := [][]byte{
		good[:len(good)-2], []byte("p10\x00cworker\x00\n"),
		bytes.ReplaceAll(good, []byte("PTCP"), []byte("PUDP")),
		bytes.ReplaceAll(good, []byte("TST=LISTEN\x00"), nil),
		bytes.ReplaceAll(good, []byte("p10"), []byte("p0")),
		bytes.ReplaceAll(good, []byte("n*:8080"), []byte("n127.0.0.1:8080->127.0.0.1:80")),
		bytes.ReplaceAll(good, []byte("n*:8080"), []byte("nlocalhost:8080")),
		bytes.ReplaceAll(good, []byte("n*:8080"), []byte("n*:0")),
		append(append([]byte{}, good...), []byte("unexpected\x00\n")...),
	}
	for i, raw := range cases {
		if _, err := parsePortRecords(raw, 8080); err == nil {
			t.Fatalf("case %d accepted malformed data %q", i, raw)
		}
	}
}

func TestPortRecordsKeepScopedIPv6InterfacesDistinct(t *testing.T) {
	raw := listenerRecord("10", "worker", "IPv6", "[fe80::1%en0]:8080")
	raw = append(raw, listenerRecord("10", "worker", "IPv6", "[fe80::1%en1]:8080")...)
	matches, err := parsePortRecords(raw, 8080)
	if err != nil || len(matches) != 2 || matches[0].Address != "fe80::1%en0" || matches[1].Address != "fe80::1%en1" {
		t.Fatalf("IPv6 zone lost: %+v %v", matches, err)
	}
	wrongFamily := listenerRecord("10", "worker", "IPv4", "[::1]:8080")
	if _, err := parsePortRecords(wrongFamily, 8080); err == nil {
		t.Fatal("mismatched address family accepted")
	}
}

func fakePortDependencies(raw []byte) portDependencies {
	identity := portIdentity{Seconds: 10, Microseconds: 42, Name: "worker"}
	return portDependencies{
		Scan: func(context.Context, int) ([]byte, []byte, error) { return raw, nil, nil },
		Snapshot: func(context.Context) (map[int]portIdentity, error) {
			return map[int]portIdentity{10: identity}, nil
		},
		Identity: func(context.Context, int) (portIdentity, error) { return identity, nil },
		Path: func(context.Context, int) (string, error) {
			return "/Applications/Worker.app/Contents/MacOS/Worker", nil
		},
	}
}

func TestPortMetadataUnknownRetainsListener(t *testing.T) {
	for _, scenario := range []string{"known", "no-snapshot", "new-pid", "reused-pid", "exec-changed", "exited", "path-failed"} {
		t.Run(scenario, func(t *testing.T) {
			deps := fakePortDependencies(listenerRecord("10", "worker", "IPv4", "*:8080"))
			switch scenario {
			case "no-snapshot":
				deps.Snapshot = func(context.Context) (map[int]portIdentity, error) { return nil, errors.New("denied") }
			case "new-pid":
				deps.Snapshot = func(context.Context) (map[int]portIdentity, error) { return map[int]portIdentity{}, nil }
			case "reused-pid":
				deps.Identity = func(context.Context, int) (portIdentity, error) { return portIdentity{10, 43, "worker"}, nil }
			case "exec-changed":
				calls := 0
				deps.Identity = func(context.Context, int) (portIdentity, error) {
					calls++
					name := "worker"
					if calls > 1 {
						name = "new-worker"
					}
					return portIdentity{10, 42, name}, nil
				}
			case "exited":
				deps.Identity = func(context.Context, int) (portIdentity, error) { return portIdentity{}, errors.New("gone") }
			case "path-failed":
				deps.Path = func(context.Context, int) (string, error) { return "", errors.New("denied") }
			}
			result := collectPortQuery(context.Background(), 8080, deps)
			if result.Error != nil || len(result.Matches) != 1 || result.Complete || result.Visibility != "visible_processes" {
				t.Fatalf("unexpected result: %+v", result)
			}
			if (result.Matches[0].Path != nil) != (scenario == "known") {
				t.Fatalf("wrong path availability for %s: %+v", scenario, result.Matches[0])
			}
		})
	}
}

func TestPortScanEmptyDiagnosticsAndFailures(t *testing.T) {
	exitOne := exec.Command("/bin/sh", "-c", "exit 1").Run()
	for _, tc := range []struct {
		name        string
		out, stderr []byte
		err         error
		kind        string
	}{
		{"empty", nil, nil, exitOne, ""},
		{"empty-success", nil, nil, nil, ""},
		{"permission", nil, []byte("Operation not permitted"), exitOne, "permission_denied"},
		{"permission-before-start", nil, nil, os.ErrPermission, "permission_denied"},
		{"warning", listenerRecord("10", "worker", "IPv4", "*:8080"), []byte("warning"), nil, "diagnostic_output"},
		{"partial-failed", listenerRecord("10", "worker", "IPv4", "*:8080"), nil, exitOne, "collection_failed"},
		{"missing", nil, nil, os.ErrNotExist, "tool_unavailable"},
		{"malformed", []byte("junk"), nil, nil, "malformed_output"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			deps := fakePortDependencies(nil)
			deps.Scan = func(context.Context, int) ([]byte, []byte, error) { return tc.out, tc.stderr, tc.err }
			result := collectPortQuery(context.Background(), 8080, deps)
			if tc.kind == "" {
				if result.Error != nil || result.ScanStatus != "ok" || result.Matches == nil {
					t.Fatalf("empty result: %+v", result)
				}
			} else if result.Error == nil || result.Error.Kind != tc.kind {
				t.Fatalf("expected %s: %+v", tc.kind, result)
			}
			if result.Complete {
				t.Fatal("unprivileged query claimed complete system visibility")
			}
		})
	}
}

func TestPortQuerySharesDeadlineAcrossMetadata(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	deps := fakePortDependencies(listenerRecord("10", "worker", "IPv4", "*:8080"))
	deps.Path = func(got context.Context, _ int) (string, error) {
		if got != ctx {
			t.Fatal("metadata received a fresh deadline")
		}
		<-got.Done()
		return "", got.Err()
	}
	result := collectPortQuery(ctx, 8080, deps)
	if result.Error == nil || result.Error.Kind != "timeout" || len(result.Matches) != 1 || result.Matches[0].Path != nil {
		t.Fatalf("deadline lost: %+v", result)
	}
	ctx, stop := context.WithCancel(context.Background())
	stop()
	deps.Scan = func(context.Context, int) ([]byte, []byte, error) {
		t.Fatal("scan started after cancellation")
		return nil, nil, nil
	}
	if result = collectPortQuery(ctx, 8080, deps); result.Error == nil || result.Error.Kind != "cancelled" {
		t.Fatalf("cancel lost: %+v", result)
	}
}

func TestPortResultTextJSONAndWriterFailures(t *testing.T) {
	result := collectPortQuery(context.Background(), 8080, fakePortDependencies(listenerRecord("10", "worker\n\x1b[2J", "IPv4", "*:8080")))
	for _, asJSON := range []bool{false, true} {
		var stdout, stderr bytes.Buffer
		if code := writePortResult(&stdout, &stderr, result, asJSON); code != 0 || stderr.Len() != 0 {
			t.Fatalf("output failed: %d %s", code, &stderr)
		}
		if asJSON {
			var decoded portResult
			if err := json.Unmarshal(stdout.Bytes(), &decoded); err != nil || decoded.Matches[0].Name != result.Matches[0].Name || decoded.Complete {
				t.Fatalf("JSON lost contract: %+v %v", decoded, err)
			}
		} else if strings.Contains(stdout.String(), "\x1b") || strings.Contains(stdout.String(), "worker\n") || !strings.Contains(stdout.String(), "does not prove the port is free") {
			t.Fatalf("unsafe/misleading terminal output: %q", &stdout)
		}
	}
	reader, writer := io.Pipe()
	_ = reader.Close()
	defer writer.Close()
	var stderr bytes.Buffer
	if writePortResult(writer, &stderr, result, true) != 1 {
		t.Fatal("output failure returned success")
	}
}

func TestPortResultErrorsRemainDistinctInTextAndJSON(t *testing.T) {
	for _, kind := range []string{"permission_denied", "tool_unavailable", "timeout", "cancelled", "malformed_output"} {
		for _, asJSON := range []bool{false, true} {
			result := portResult{Query: portOperand{"TCP", 8080}, Matches: []portMatch{}, Visibility: "visible_processes"}
			result = failPortQuery(result, errors.New("probe unavailable"), kind)
			var stdout, stderr bytes.Buffer
			code := writePortResult(&stdout, &stderr, result, asJSON)
			want := 1
			if kind == "cancelled" {
				want = 130
			}
			if code != want || !strings.Contains(stderr.String(), kind) || strings.Contains(stdout.String(), "No visible TCP listeners found") {
				t.Fatalf("cause hidden: kind=%s json=%v code=%d stdout=%q stderr=%q", kind, asJSON, code, &stdout, &stderr)
			}
			if asJSON {
				var decoded portResult
				if err := json.Unmarshal(stdout.Bytes(), &decoded); err != nil || decoded.Error.Kind != kind || decoded.Complete {
					t.Fatalf("wrong failure JSON: %+v %v", decoded, err)
				}
			}
		}
	}
}

func TestPortCommandCancellationKillsOwnedChildren(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "child-pid")
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	started := time.Now()
	_, _, err := runPortCommand(ctx, "/bin/sh", "-c", `sleep 30 & echo $! > "$1"; wait`, "test", pidFile)
	if err == nil || time.Since(started) > time.Second {
		t.Fatalf("command did not stop within budget: %v", err)
	}
	data, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		t.Fatal(err)
	}
	// macOS may retain a killed child as a zombie briefly. It must not keep
	// running or holding the query's inherited descriptors after cancellation.
	for range 20 {
		if err := syscall.Kill(pid, 0); errors.Is(err, syscall.ESRCH) {
			return
		}
		status, _ := exec.Command("/bin/ps", "-p", strings.TrimSpace(string(data)), "-o", "stat=").Output()
		if strings.HasPrefix(strings.TrimSpace(string(status)), "Z") || len(status) == 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("producer child survived cancellation")
}
