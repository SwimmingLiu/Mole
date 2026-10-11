package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"
	"unicode"
)

const portQueryTimeout = 3 * time.Second
const portCommandDrainTime = 50 * time.Millisecond
const portOutputLimit = 4 << 20

type portMatch struct {
	Protocol string  `json:"protocol"`
	Family   string  `json:"family"`
	Address  string  `json:"address"`
	Port     int     `json:"port"`
	PID      int     `json:"pid"`
	Name     string  `json:"name"`
	Path     *string `json:"path"`
}

type portResult struct {
	CollectedAt time.Time   `json:"collected_at"`
	Query       portOperand `json:"query"`
	Matches     []portMatch `json:"matches"`
	Visibility  string      `json:"visibility"`
	Complete    bool        `json:"complete"`
	ScanStatus  string      `json:"scan_status"`
	Error       *portError  `json:"error"`
}

type portOperand struct {
	Protocol string `json:"protocol"`
	Port     int    `json:"port"`
}

type portError struct {
	Kind    string `json:"kind"`
	Message string `json:"message"`
}

// Native start time and command evidence bracket lsof so a reused PID cannot
// acquire an unrelated executable path after the listener snapshot.
type portIdentity struct {
	Seconds, Microseconds int64
	Name                  string
}

type portDependencies struct {
	Scan     func(context.Context, int) ([]byte, []byte, error)
	Snapshot func(context.Context) (map[int]portIdentity, error)
	Identity func(context.Context, int) (portIdentity, error)
	Path     func(context.Context, int) (string, error)
}

func portQuerySelected() bool {
	selected := false
	flag.CommandLine.Visit(func(f *flag.Flag) {
		if f.Name == "port" {
			selected = true
		}
	})
	return selected
}

func parsePort(raw string) (int, error) {
	if raw != "" && !strings.ContainsFunc(raw, func(r rune) bool { return r < '0' || r > '9' }) {
		port, err := strconv.Atoi(raw)
		if err == nil && port >= 1 && port <= 65535 {
			return port, nil
		}
	}
	return 0, fmt.Errorf("--port must be a decimal number from 1 to 65535")
}

func collectPortQuery(ctx context.Context, port int, deps portDependencies) portResult {
	result := portResult{
		CollectedAt: time.Now(), Query: portOperand{"TCP", port}, Matches: []portMatch{},
		Visibility: "visible_processes", Complete: false, ScanStatus: "ok",
	}
	before, _ := deps.Snapshot(ctx) // Missing identity evidence keeps paths unknown, not listeners absent.
	if err := ctx.Err(); err != nil {
		return failPortQuery(result, err, "")
	}
	out, diagnostics, err := deps.Scan(ctx, port)
	if ctx.Err() != nil {
		return failPortQuery(result, ctx.Err(), "")
	}
	if len(out) > 0 {
		matches, parseErr := parsePortRecords(out, port)
		if parseErr != nil {
			return failPortQuery(result, parseErr, "malformed_output")
		}
		result.Matches = matches
	}
	// lsof uses exit 1 for no selection, but warnings or partial bytes are not
	// evidence of an empty scan. Never fold them into a successful zero result.
	var exitErr *exec.ExitError
	noMatch := errors.As(err, &exitErr) && exitErr.ExitCode() == 1 && len(out) == 0 && len(diagnostics) == 0
	if err != nil && !noMatch {
		kind := "collection_failed"
		if errors.Is(err, exec.ErrNotFound) || errors.Is(err, os.ErrNotExist) {
			kind = "tool_unavailable"
		}
		if errors.Is(err, os.ErrPermission) || permissionDiagnostic(diagnostics) {
			kind = "permission_denied"
		}
		return failPortQuery(result, fmt.Errorf("could not collect visible TCP listeners"), kind)
	}
	if len(diagnostics) > 0 {
		kind := "diagnostic_output"
		if permissionDiagnostic(diagnostics) {
			kind = "permission_denied"
		}
		return failPortQuery(result, fmt.Errorf("lsof reported diagnostics; listener scan is incomplete"), kind)
	}
	paths := make(map[int]*string)
	for i := range result.Matches {
		match := &result.Matches[i]
		if path, ok := paths[match.PID]; ok {
			match.Path = path
			continue
		}
		paths[match.PID] = nil
		old, known := before[match.PID]
		if !known {
			continue
		}
		current, identityErr := deps.Identity(ctx, match.PID)
		if identityErr != nil || current != old {
			continue
		}
		path, pathErr := deps.Path(ctx, match.PID)
		after, identityErr := deps.Identity(ctx, match.PID)
		if pathErr == nil && identityErr == nil && after == old && filepath.IsAbs(path) {
			paths[match.PID] = &path
			match.Path = &path
		}
		if ctx.Err() != nil {
			return failPortQuery(result, ctx.Err(), "")
		}
	}
	if ctx.Err() != nil {
		return failPortQuery(result, ctx.Err(), "")
	}
	return result
}

func permissionDiagnostic(raw []byte) bool {
	text := strings.ToLower(string(raw))
	return strings.Contains(text, "permission denied") || strings.Contains(text, "operation not permitted")
}

func failPortQuery(result portResult, err error, kind string) portResult {
	if errors.Is(err, context.DeadlineExceeded) {
		kind = "timeout"
		err = fmt.Errorf("TCP listener query exceeded its three-second budget")
	} else if errors.Is(err, context.Canceled) {
		kind = "cancelled"
		err = fmt.Errorf("TCP listener query cancelled")
	}
	if kind == "" {
		kind = "collection_failed"
	}
	result.ScanStatus = kind
	result.Error = &portError{kind, err.Error()}
	return result
}

func parsePortRecords(raw []byte, port int) ([]portMatch, error) {
	bad := func() ([]portMatch, error) { return nil, fmt.Errorf("invalid lsof listener records") }
	if len(raw) == 0 || !bytes.HasSuffix(raw, []byte{0, '\n'}) {
		return bad()
	}
	var pid int
	var name string
	var fd, family, protocol, address, state string
	seen := make(map[string]bool)
	hadFile := false
	matches := []portMatch{}
	flush := func() error {
		if fd == "" {
			return nil
		}
		if pid <= 0 || name == "" || (family != "IPv4" && family != "IPv6") || protocol != "TCP" || state == "" || address == "" {
			return fmt.Errorf("incomplete listener record")
		}
		host, number, err := net.SplitHostPort(address)
		if err != nil || strings.Contains(address, "->") {
			return fmt.Errorf("invalid local endpoint")
		}
		n, err := strconv.Atoi(number)
		if err != nil || n < 1 || n > 65535 {
			return fmt.Errorf("invalid local port")
		}
		if host != "*" {
			ip := net.ParseIP(host)
			if ip == nil {
				return fmt.Errorf("non-numeric listener address")
			}
			host = ip.String()
		}
		if n == port && state == "LISTEN" {
			key := fmt.Sprintf("%d/%s/%s", pid, family, host)
			if !seen[key] {
				matches = append(matches, portMatch{Protocol: "TCP", Family: family, Address: host, Port: port, PID: pid, Name: name})
				seen[key] = true
			}
		}
		return nil
	}
	for field := range bytes.SplitSeq(raw, []byte{0}) {
		field = bytes.TrimPrefix(field, []byte{'\n'}) // lsof inserts one newline between NUL field sets.
		if len(field) == 0 {
			continue
		}
		value := string(field[1:])
		switch field[0] {
		case 'p', 'f':
			if err := flush(); err != nil {
				return bad()
			}
			fd, family, protocol, address, state = "", "", "", "", ""
			if field[0] == 'p' {
				var err error
				pid, err = strconv.Atoi(value)
				if err != nil || pid <= 0 {
					return bad()
				}
				name = ""
			} else {
				if pid <= 0 || value == "" {
					return bad()
				}
				fd = value
				hadFile = true
			}
		case 'c':
			if pid <= 0 || fd != "" || name != "" || value == "" {
				return bad()
			}
			name = value
		case 't', 'P', 'n', 'T':
			if fd == "" {
				return bad()
			}
			var target *string
			switch field[0] {
			case 't':
				target = &family
			case 'P':
				target = &protocol
			case 'n':
				target = &address
			case 'T':
				if !strings.HasPrefix(value, "ST=") {
					continue
				}
				value, target = strings.TrimPrefix(value, "ST="), &state
			}
			if *target != "" || value == "" {
				return bad()
			}
			*target = value
		default:
			return bad()
		}
	}
	if err := flush(); err != nil {
		return bad()
	}
	if !hadFile {
		return bad()
	}
	slices.SortFunc(matches, func(a, b portMatch) int {
		if a.PID != b.PID {
			return a.PID - b.PID
		}
		if a.Family != b.Family {
			return strings.Compare(a.Family, b.Family)
		}
		return strings.Compare(a.Address, b.Address)
	})
	return matches, nil
}

type boundedPortBuffer struct {
	bytes.Buffer
}

func (b *boundedPortBuffer) Write(p []byte) (int, error) {
	if len(p) > portOutputLimit-b.Len() {
		return 0, fmt.Errorf("listener output exceeds limit")
	}
	return b.Buffer.Write(p)
}

func scanPort(ctx context.Context, port int) ([]byte, []byte, error) {
	return runPortCommand(ctx, "/usr/sbin/lsof", "-nP", "+c", "0", "-a", "-iTCP:"+strconv.Itoa(port), "-sTCP:LISTEN", "-F0pcftPnT")
}

func runPortCommand(ctx context.Context, executable string, args ...string) ([]byte, []byte, error) {
	cmd := exec.CommandContext(ctx, executable, args...)
	cmd.Env = cLocaleEnv()
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	// Kill the owned group, including inherited pipe writers, on cancellation
	// and after completion. A wrapper must not leave work behind the deadline.
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = portCommandDrainTime
	var stdout, stderr boundedPortBuffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	if cmd.Process != nil {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	return stdout.Bytes(), stderr.Bytes(), err
}

func runPortQuery(port int, asJSON bool, stdout, stderr io.Writer) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	// Reserve pipe-drain time inside the advertised total budget, rather than
	// allowing CommandContext cleanup to extend a three-second scan deadline.
	ctx, cancel := context.WithTimeout(ctx, portQueryTimeout-portCommandDrainTime)
	defer cancel()
	deps := portDependencies{scanPort, snapshotPortIdentities, readPortIdentity, readPortPath}
	var result portResult
	if runtime.GOOS != "darwin" {
		result = portResult{Query: portOperand{"TCP", port}, Matches: []portMatch{}, Visibility: "visible_processes", CollectedAt: time.Now()}
		result = failPortQuery(result, fmt.Errorf("TCP listener queries require macOS"), "unsupported_platform")
	} else {
		result = collectPortQuery(ctx, port, deps)
	}
	return writePortResult(stdout, stderr, result, asJSON)
}

func writePortResult(stdout, stderr io.Writer, result portResult, asJSON bool) int {
	var err error
	if asJSON {
		err = json.NewEncoder(stdout).Encode(result)
	} else {
		var table bytes.Buffer
		fmt.Fprintf(&table, "TCP port %d · visible listeners\n", result.Query.Port)
		if len(result.Matches) == 0 {
			if result.Error == nil {
				fmt.Fprintln(&table, "No visible TCP listeners found.")
			} else {
				fmt.Fprintln(&table, "Listener results unavailable.")
			}
		} else {
			w := tabwriter.NewWriter(&table, 0, 4, 2, ' ', 0)
			_, _ = fmt.Fprintln(w, "PID\tPROCESS\tPROTOCOL\tLISTEN\tPATH")
			for _, match := range result.Matches {
				path := "unknown"
				if match.Path != nil {
					path = *match.Path
				}
				_, _ = fmt.Fprintf(w, "%d\t%s\t%s/%s\t%s\t%s\n", match.PID, escapePortText(match.Name), match.Protocol, match.Family, net.JoinHostPort(match.Address, strconv.Itoa(match.Port)), escapePortText(path))
			}
			_ = w.Flush()
		}
		fmt.Fprintln(&table, "Visibility is limited to accessible processes; this does not prove the port is free.")
		_, err = stdout.Write(table.Bytes())
	}
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "status: could not write TCP listener results")
		return 1
	}
	if result.Error != nil {
		_, _ = fmt.Fprintf(stderr, "status: TCP listener query %s: %s\n", result.Error.Kind, escapePortText(result.Error.Message))
		if result.Error.Kind == "cancelled" {
			return 130
		}
		return 1
	}
	return 0
}

func escapePortText(raw string) string {
	var escaped strings.Builder
	for _, r := range raw {
		if unicode.IsControl(r) || unicode.In(r, unicode.Cf) {
			fmt.Fprintf(&escaped, "\\u%04x", r)
		} else {
			escaped.WriteRune(r)
		}
	}
	return escaped.String()
}
