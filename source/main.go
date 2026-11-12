package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"
)

type Config struct {
	Limit       int
	Sort        string
	Watch       bool
	Interval    time.Duration
	Verbose     bool
	Zombie      bool
	Threads     bool
	ThreadLimit int
	Tree        bool
	Wide        bool
	Details     bool
	JSON        bool
	Filter      string
}

type ProcKey struct {
	PID       int
	StartTime uint64
	Thread    bool
}

type CPUPoint struct {
	Ticks      uint64
	ReadBytes  uint64
	WriteBytes uint64
}

type Process struct {
	PID        int
	PPID       int
	CPU        float64
	MemoryMB   float64
	RSSBytes   uint64
	Cmd        string
	Comm       string
	State      byte
	Ticks      uint64
	StartTime  uint64
	Elapsed    time.Duration
	Kind       string
	FDCount    int
	ReadBytes  uint64
	WriteBytes uint64
	ReadRate   float64
	WriteRate  float64
	Cgroup     string
	Unit       string
}

type ProcStat struct {
	Comm      string
	State     byte
	PPID      int
	UTime     uint64
	STime     uint64
	CUTime    int64
	CSTime    int64
	StartTime uint64
}

type Snapshot struct {
	Processes []Process
	Points    map[ProcKey]CPUPoint
	Scanned   int
	Skipped   int
	Uptime    time.Duration
	TakenAt   time.Time
	System    SystemStats
}

type Pressure struct {
	Some      float64 `json:"some_avg10"`
	Full      float64 `json:"full_avg10"`
	Available bool    `json:"available"`
}

type SystemStats struct {
	MemTotal     uint64   `json:"mem_total_bytes"`
	MemAvailable uint64   `json:"mem_available_bytes"`
	SwapTotal    uint64   `json:"swap_total_bytes"`
	SwapFree     uint64   `json:"swap_free_bytes"`
	Load1        float64  `json:"load1"`
	Load5        float64  `json:"load5"`
	Load15       float64  `json:"load15"`
	CPU          Pressure `json:"cpu_pressure"`
	Memory       Pressure `json:"memory_pressure"`
	IO           Pressure `json:"io_pressure"`
}

type Monitor struct {
	config   Config
	hertz    float64
	cpuCount int
	pageSize uint64
}

const (
	defaultLimit      = 20
	defaultInterval   = 2 * time.Second
	defaultHertz      = 100.0
	defaultPageSize   = 4096
	maxLimit          = 10000
	maxThreadLimit    = 100000
	maxCommandRunes   = 120
	maxTreeDepth      = 256
	minProcStatFields = 20
	processKind       = "process"
	threadKind        = "thread"
)

func main() {
	config, err := parseArgs()
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(2)
	}

	monitor, err := newMonitor(config)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := monitor.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}

func parseArgs() (Config, error) {
	var config Config
	var interval int

	flag.IntVar(&config.Limit, "limit", defaultLimit, "number of entries to show")
	flag.StringVar(&config.Sort, "sort", "cpu", "sort by cpu, mem, pid, time, command, state")
	flag.BoolVar(&config.Watch, "watch", false, "enable watch mode")
	flag.IntVar(&interval, "interval", int(defaultInterval/time.Second), "refresh interval in seconds")
	flag.BoolVar(&config.Verbose, "verbose", false, "show diagnostic information")
	flag.BoolVar(&config.Zombie, "zombie", false, "include zombie processes")
	flag.BoolVar(&config.Threads, "threads", false, "include threads")
	flag.IntVar(&config.ThreadLimit, "thread-limit", 1000, "maximum threads to read per process")
	flag.BoolVar(&config.Tree, "tree", false, "show process tree")
	flag.BoolVar(&config.Wide, "wide", false, "do not truncate command lines")
	flag.BoolVar(&config.Details, "details", false, "show I/O, FDs, cgroup and systemd unit")
	flag.BoolVar(&config.JSON, "json", false, "output a JSON snapshot (or JSON lines in watch mode)")
	flag.StringVar(&config.Filter, "filter", "", "case-insensitive command substring filter")

	flag.Usage = func() {
		out := flag.CommandLine.Output()
		fmt.Fprintf(out, "Linux procfs process monitor\n\nUsage: %s [OPTIONS]\n\n", filepath.Base(os.Args[0]))
		flag.PrintDefaults()
		fmt.Fprintf(out, "\nExamples:\n  %s -limit 10 -sort mem\n  %s -watch -interval 1\n  %s -threads -watch\n  %s -tree -limit 50\n",
			filepath.Base(os.Args[0]),
			filepath.Base(os.Args[0]),
			filepath.Base(os.Args[0]),
			filepath.Base(os.Args[0]))
	}

	flag.Parse()

	if config.Limit < 1 || config.Limit > maxLimit {
		return Config{}, fmt.Errorf("limit must be between 1 and %d", maxLimit)
	}

	if interval < 1 || interval > 3600 {
		return Config{}, errors.New("interval must be between 1 and 3600 seconds")
	}

	config.Interval = time.Duration(interval) * time.Second

	if config.ThreadLimit < 1 || config.ThreadLimit > maxThreadLimit {
		return Config{}, fmt.Errorf("thread-limit must be between 1 and %d", maxThreadLimit)
	}

	config.Sort = strings.ToLower(strings.TrimSpace(config.Sort))

	valid := map[string]bool{
		"cpu":     true,
		"mem":     true,
		"pid":     true,
		"time":    true,
		"command": true,
		"state":   true,
	}

	if !valid[config.Sort] {
		return Config{}, fmt.Errorf("invalid sort %q", config.Sort)
	}

	if config.Tree {
		config.Zombie = true
	}

	return config, nil
}

func newMonitor(config Config) (*Monitor, error) {
	if runtime.GOOS != "linux" {
		return nil, errors.New("this tool only works on Linux")
	}

	if err := validateProcFS(); err != nil {
		return nil, err
	}

	m := &Monitor{
		config:   config,
		hertz:    detectHertz(),
		cpuCount: runtime.NumCPU(),
		pageSize: uint64(os.Getpagesize()),
	}

	if m.hertz <= 0 {
		m.hertz = defaultHertz
	}

	if m.cpuCount < 1 {
		m.cpuCount = 1
	}

	if m.pageSize == 0 {
		m.pageSize = defaultPageSize
	}

	return m, nil
}

func validateProcFS() error {
	info, err := os.Stat("/proc/self/stat")
	if err != nil {
		return fmt.Errorf("procfs is unavailable: %w", err)
	}

	if !info.Mode().IsRegular() {
		return errors.New("/proc/self/stat is not a regular procfs entry")
	}

	return nil
}

func detectHertz() float64 {
	path, err := exec.LookPath("getconf")
	if err != nil {
		return defaultHertz
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx, path, "CLK_TCK").Output()
	if err != nil {
		return defaultHertz
	}

	hz, err := strconv.ParseFloat(strings.TrimSpace(string(out)), 64)
	if err != nil || hz <= 0 || math.IsNaN(hz) || math.IsInf(hz, 0) {
		return defaultHertz
	}

	return hz
}

func (m *Monitor) Run(ctx context.Context) error {
	if m.config.Watch {
		return m.runWatch(ctx)
	}

	snapshot, err := m.takeSnapshot()
	if err != nil {
		return err
	}

	m.assignLifetimeCPU(&snapshot)
	if m.config.JSON {
		return m.renderJSON(snapshot)
	}
	m.render(snapshot, false, 1)

	return nil
}

func (m *Monitor) runWatch(ctx context.Context) error {
	previous, err := m.takeSnapshot()
	if err != nil {
		return err
	}

	iteration := 1
	m.assignLifetimeCPU(&previous)
	if m.config.JSON {
		if err := m.renderJSON(previous); err != nil {
			return err
		}
	} else {
		m.clearScreen()
		m.render(previous, true, iteration)
	}

	ticker := time.NewTicker(m.config.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			fmt.Println()
			return ctx.Err()

		case <-ticker.C:
			current, err := m.takeSnapshot()
			if err != nil {
				if m.config.Verbose {
					fmt.Fprintln(os.Stderr, "Snapshot error:", err)
				}
				continue
			}

			m.assignDeltaCPU(&current, previous)

			iteration++
			if m.config.JSON {
				if err := m.renderJSON(current); err != nil {
					return err
				}
			} else {
				m.clearScreen()
				m.render(current, true, iteration)
			}

			previous = current
		}
	}
}

func (m *Monitor) clearScreen() {
	fmt.Print("\033[2J\033[H")
}

func (m *Monitor) takeSnapshot() (Snapshot, error) {
	uptime, err := readUptime()
	if err != nil {
		return Snapshot{}, err
	}

	entries, err := os.ReadDir("/proc")
	if err != nil {
		return Snapshot{}, fmt.Errorf("cannot read /proc: %w", err)
	}

	snapshot := Snapshot{
		Processes: make([]Process, 0, len(entries)),
		Points:    make(map[ProcKey]CPUPoint, len(entries)),
		Uptime:    uptime,
		TakenAt:   time.Now(),
		System:    readSystemStats(),
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 0 {
			continue
		}

		snapshot.Scanned++

		proc, err := m.readProcess(pid, uptime)
		if err != nil {
			snapshot.Skipped++

			if m.config.Verbose && !isTransientProcError(err) {
				fmt.Fprintf(os.Stderr, "PID %d: %v\n", pid, err)
			}

			continue
		}

		if m.config.Filter != "" && !strings.Contains(strings.ToLower(proc.Cmd), strings.ToLower(m.config.Filter)) {
			continue
		}
		if proc.State == 'Z' && !m.config.Zombie {
			continue
		}

		snapshot.Processes = append(snapshot.Processes, proc)
		snapshot.Points[proc.key()] = CPUPoint{
			Ticks: proc.Ticks, ReadBytes: proc.ReadBytes, WriteBytes: proc.WriteBytes,
		}

		if m.config.Threads {
			threads := m.readThreads(pid, uptime)

			for _, thread := range threads {
				if thread.State == 'Z' && !m.config.Zombie {
					continue
				}

				snapshot.Processes = append(snapshot.Processes, thread)
				snapshot.Points[thread.key()] = CPUPoint{
					Ticks: thread.Ticks,
				}
			}
		}
	}

	return snapshot, nil
}

func (p Process) key() ProcKey {
	return ProcKey{
		PID:       p.PID,
		StartTime: p.StartTime,
		Thread:    p.Kind == threadKind,
	}
}

func isTransientProcError(err error) bool {
	return errors.Is(err, os.ErrNotExist) ||
		errors.Is(err, os.ErrPermission)
}

func readUptime() (time.Duration, error) {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0, fmt.Errorf("cannot read /proc/uptime: %w", err)
	}

	fields := strings.Fields(string(data))
	if len(fields) == 0 {
		return 0, errors.New("invalid /proc/uptime")
	}

	seconds, err := strconv.ParseFloat(fields[0], 64)
	if err != nil ||
		seconds < 0 ||
		math.IsNaN(seconds) ||
		math.IsInf(seconds, 0) {
		return 0, errors.New("invalid uptime value")
	}

	return time.Duration(seconds * float64(time.Second)), nil
}

func parseProcStat(data []byte) (ProcStat, error) {
	line := strings.TrimSpace(string(data))

	left := strings.IndexByte(line, '(')
	right := strings.LastIndexByte(line, ')')

	if left < 0 || right <= left || right+2 > len(line) {
		return ProcStat{}, errors.New("invalid stat format")
	}

	comm := line[left+1 : right]
	fields := strings.Fields(line[right+1:])

	if len(fields) < minProcStatFields {
		return ProcStat{}, fmt.Errorf(
			"stat has %d fields after comm",
			len(fields),
		)
	}

	if len(fields[0]) != 1 {
		return ProcStat{}, errors.New("invalid process state")
	}

	ppid, err := strconv.Atoi(fields[1])
	if err != nil {
		return ProcStat{}, fmt.Errorf("invalid ppid: %w", err)
	}

	utime, err := strconv.ParseUint(fields[11], 10, 64)
	if err != nil {
		return ProcStat{}, fmt.Errorf("invalid utime: %w", err)
	}

	stime, err := strconv.ParseUint(fields[12], 10, 64)
	if err != nil {
		return ProcStat{}, fmt.Errorf("invalid stime: %w", err)
	}

	cutime, err := strconv.ParseInt(fields[13], 10, 64)
	if err != nil {
		return ProcStat{}, fmt.Errorf("invalid cutime: %w", err)
	}

	cstime, err := strconv.ParseInt(fields[14], 10, 64)
	if err != nil {
		return ProcStat{}, fmt.Errorf("invalid cstime: %w", err)
	}

	start, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return ProcStat{}, fmt.Errorf("invalid starttime: %w", err)
	}

	return ProcStat{
		Comm:      comm,
		State:     fields[0][0],
		PPID:      ppid,
		UTime:     utime,
		STime:     stime,
		CUTime:    cutime,
		CSTime:    cstime,
		StartTime: start,
	}, nil
}

func (m *Monitor) readProcess(
	pid int,
	uptime time.Duration,
) (Process, error) {
	base := filepath.Join("/proc", strconv.Itoa(pid))

	data, err := os.ReadFile(filepath.Join(base, "stat"))
	if err != nil {
		return Process{}, err
	}

	stat, err := parseProcStat(data)
	if err != nil {
		return Process{}, err
	}

	rss, err := readRSSBytes(filepath.Join(base, "status"))
	if err != nil &&
		m.config.Verbose &&
		!isTransientProcError(err) {
		fmt.Fprintf(
			os.Stderr,
			"PID %d memory: %v\n",
			pid,
			err,
		)
	}

	cmd := readCommand(
		filepath.Join(base, "cmdline"),
		stat.Comm,
		m.config.Wide,
	)

	ticks := stat.UTime + stat.STime

	elapsed := uptime - m.ticksDuration(stat.StartTime)
	if elapsed < 0 {
		elapsed = 0
	}

	readBytes, writeBytes := readProcessIO(filepath.Join(base, "io"))
	fdCount := readFDCount(filepath.Join(base, "fd"))
	cgroup := readCgroup(filepath.Join(base, "cgroup"))

	return Process{
		FDCount:    fdCount,
		ReadBytes:  readBytes,
		WriteBytes: writeBytes,
		Cgroup:     cgroup,
		Unit:       systemdUnit(cgroup),
		PID:        pid,
		PPID:       stat.PPID,
		MemoryMB:   bytesToMB(rss),
		RSSBytes:   rss,
		Cmd:        cmd,
		Comm:       stat.Comm,
		State:      stat.State,
		Ticks:      ticks,
		StartTime:  stat.StartTime,
		Elapsed:    elapsed,
		Kind:       processKind,
	}, nil
}

func (m *Monitor) readThreads(
	pid int,
	uptime time.Duration,
) []Process {
	taskDir := filepath.Join(
		"/proc",
		strconv.Itoa(pid),
		"task",
	)

	entries, err := os.ReadDir(taskDir)
	if err != nil {
		return nil
	}

	threads := make(
		[]Process,
		0,
		minInt(len(entries), m.config.ThreadLimit),
	)

	count := 0

	for _, entry := range entries {
		if count >= m.config.ThreadLimit {
			break
		}

		if !entry.IsDir() {
			continue
		}

		tid, err := strconv.Atoi(entry.Name())
		if err != nil || tid <= 0 || tid == pid {
			continue
		}

		data, err := os.ReadFile(
			filepath.Join(
				taskDir,
				entry.Name(),
				"stat",
			),
		)
		if err != nil {
			continue
		}

		stat, err := parseProcStat(data)
		if err != nil {
			continue
		}

		ticks := stat.UTime + stat.STime

		elapsed := uptime - m.ticksDuration(stat.StartTime)
		if elapsed < 0 {
			elapsed = 0
		}

		threads = append(
			threads,
			Process{
				PID:       tid,
				PPID:      pid,
				Cmd:       "└─ " + sanitizeText(stat.Comm),
				Comm:      stat.Comm,
				State:     stat.State,
				Ticks:     ticks,
				StartTime: stat.StartTime,
				Elapsed:   elapsed,
				Kind:      threadKind,
			},
		)

		count++
	}

	return threads
}

func readRSSBytes(path string) (uint64, error) {
	file, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()

		if !strings.HasPrefix(line, "VmRSS:") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 2 {
			return 0, errors.New("invalid VmRSS line")
		}

		kb, err := strconv.ParseUint(
			fields[1],
			10,
			64,
		)
		if err != nil {
			return 0, err
		}

		return kb * 1024, nil
	}

	if err := scanner.Err(); err != nil {
		return 0, err
	}

	return 0, nil
}

func readCommand(
	path string,
	fallback string,
	wide bool,
) string {
	data, err := os.ReadFile(path)

	if err != nil || len(data) == 0 {
		return "[" + sanitizeText(fallback) + "]"
	}

	parts := strings.Split(string(data), "\x00")
	clean := make([]string, 0, len(parts))

	for _, part := range parts {
		part = sanitizeText(part)

		if part != "" {
			clean = append(clean, part)
		}
	}

	cmd := strings.Join(clean, " ")

	if cmd == "" {
		cmd = "[" + sanitizeText(fallback) + "]"
	}

	if !wide {
		cmd = truncateRunes(cmd, maxCommandRunes)
	}

	return cmd
}

func sanitizeText(s string) string {
	s = strings.TrimSpace(s)

	return strings.Map(
		func(r rune) rune {
			if unicode.IsPrint(r) || r == '\t' {
				return r
			}

			return '?'
		},
		s,
	)
}

func truncateRunes(
	s string,
	limit int,
) string {
	if limit <= 0 ||
		utf8.RuneCountInString(s) <= limit {
		return s
	}

	if limit <= 3 {
		return strings.Repeat(".", limit)
	}

	runes := []rune(s)

	return string(runes[:limit-3]) + "..."
}

func (m *Monitor) ticksDuration(
	ticks uint64,
) time.Duration {
	seconds := float64(ticks) / m.hertz

	return time.Duration(
		seconds * float64(time.Second),
	)
}

func (m *Monitor) assignLifetimeCPU(
	snapshot *Snapshot,
) {
	for i := range snapshot.Processes {
		p := &snapshot.Processes[i]

		if p.Elapsed <= 0 {
			p.CPU = 0
			continue
		}

		cpuSeconds := float64(p.Ticks) / m.hertz

		p.CPU = clampCPU(
			100*cpuSeconds/p.Elapsed.Seconds(),
			m.cpuCount,
		)
	}
}

func (m *Monitor) assignDeltaCPU(
	current *Snapshot,
	previous Snapshot,
) {
	wall := current.TakenAt.
		Sub(previous.TakenAt).
		Seconds()

	if wall <= 0 {
		m.assignLifetimeCPU(current)
		return
	}

	for i := range current.Processes {
		p := &current.Processes[i]

		old, ok := previous.Points[p.key()]
		if !ok || p.Ticks < old.Ticks {
			p.CPU = 0
			continue
		}

		if p.ReadBytes >= old.ReadBytes {
			p.ReadRate = float64(p.ReadBytes-old.ReadBytes) / wall
		}
		if p.WriteBytes >= old.WriteBytes {
			p.WriteRate = float64(p.WriteBytes-old.WriteBytes) / wall
		}
		deltaTicks := p.Ticks - old.Ticks

		p.CPU = clampCPU(
			100*
				(float64(deltaTicks)/m.hertz)/
				wall,
			m.cpuCount,
		)
	}
}

func clampCPU(
	value float64,
	cpuCount int,
) float64 {
	if math.IsNaN(value) ||
		math.IsInf(value, 0) ||
		value < 0 {
		return 0
	}

	max := float64(cpuCount) * 100

	if value > max {
		return max
	}

	return math.Round(value*10) / 10
}

func bytesToMB(value uint64) float64 {
	return math.Round(
		(float64(value)/(1024*1024))*10,
	) / 10
}

func (m *Monitor) render(
	snapshot Snapshot,
	watch bool,
	iteration int,
) {
	processes := append(
		[]Process(nil),
		snapshot.Processes...,
	)

	m.sortProcesses(processes)

	fmt.Printf(
		"ProcStat | %s | uptime %s | CPUs %d | scanned %d | skipped %d",
		snapshot.TakenAt.Format("2006-01-02 15:04:05"),
		formatDuration(snapshot.Uptime),
		m.cpuCount,
		snapshot.Scanned,
		snapshot.Skipped,
	)

	if watch {
		fmt.Printf(
			" | iteration %d | interval %s",
			iteration,
			m.config.Interval,
		)
	}

	fmt.Println()

	fmt.Printf(
		"Sort: %s | Limit: %d",
		strings.ToUpper(m.config.Sort),
		m.config.Limit,
	)

	modes := make([]string, 0, 3)

	if m.config.Tree {
		modes = append(modes, "TREE")
	}

	if m.config.Threads {
		modes = append(modes, "THREADS")
	}

	if m.config.Zombie {
		modes = append(modes, "ZOMBIES")
	}

	if len(modes) > 0 {
		fmt.Printf(
			" | Modes: %s",
			strings.Join(modes, ","),
		)
	}

	fmt.Println()
	st := snapshot.System
	fmt.Printf("Memory %.1f/%.1f MiB used | Swap %.1f/%.1f MiB used | Load %.2f %.2f %.2f\n", bytesToMB(st.MemTotal-st.MemAvailable), bytesToMB(st.MemTotal), bytesToMB(st.SwapTotal-st.SwapFree), bytesToMB(st.SwapTotal), st.Load1, st.Load5, st.Load15)
	fmt.Printf("PSI avg10 CPU %s | MEM %s | IO %s\n", pressureString(st.CPU), pressureString(st.Memory), pressureString(st.IO))
	fmt.Println(strings.Repeat("=", 100))

	if len(processes) == 0 {
		fmt.Println("No matching processes found.")
		return
	}

	if m.config.Tree {
		m.renderTree(processes)
		return
	}

	m.renderTable(processes)
}

func (m *Monitor) sortProcesses(
	processes []Process,
) {
	sort.SliceStable(
		processes,
		func(i, j int) bool {
			a := processes[i]
			b := processes[j]

			switch m.config.Sort {
			case "mem":
				if a.RSSBytes != b.RSSBytes {
					return a.RSSBytes > b.RSSBytes
				}

			case "pid":
				return a.PID < b.PID

			case "time":
				if a.Ticks != b.Ticks {
					return a.Ticks > b.Ticks
				}

			case "command":
				if c := strings.Compare(
					strings.ToLower(a.Cmd),
					strings.ToLower(b.Cmd),
				); c != 0 {
					return c < 0
				}

			case "state":
				if a.State != b.State {
					return a.State < b.State
				}

			default:
				if a.CPU != b.CPU {
					return a.CPU > b.CPU
				}
			}

			return a.PID < b.PID
		},
	)
}

func (m *Monitor) renderTable(
	processes []Process,
) {
	limit := minInt(
		m.config.Limit,
		len(processes),
	)

	rows := processes[:limit]

	if !m.config.Details {
		fmt.Printf(
			"%-8s %-8s %-7s %-10s %-7s %-11s %s\n",
			"PID",
			"PPID",
			"CPU%",
			"RSS(MB)",
			"STATE",
			"CPU-TIME",
			"COMMAND",
		)

	}

	if m.config.Details {
		fmt.Printf("%-8s %-8s %-10s %-10s %-8s %-14s %-14s %s\n", "PID", "CPU%", "RSS(MB)", "FD", "STATE", "READ KiB/s", "WRITE KiB/s", "CGROUP / UNIT")
	}
	fmt.Println(strings.Repeat("-", 100))

	var cpuTotal float64
	var rssTotal uint64

	for _, p := range rows {
		memory := "-"

		if p.Kind == processKind {
			memory = fmt.Sprintf(
				"%.1f",
				p.MemoryMB,
			)

			rssTotal += p.RSSBytes
		}

		cpuTotal += p.CPU
		if m.config.Details {
			fd := "-"
			if p.FDCount >= 0 && p.Kind == processKind {
				fd = strconv.Itoa(p.FDCount)
			}
			group := p.Cgroup
			if group == "" {
				group = "-"
			}
			fmt.Printf("%-8d %-8.1f %-10s %-10s %-8s %-14.1f %-14.1f %s [%s]\n", p.PID, p.CPU, memory, fd, stateName(p.State), p.ReadRate/1024, p.WriteRate/1024, group, p.Unit)
			continue
		}

		fmt.Printf(
			"%-8d %-8d %-7.1f %-10s %-7s %-11s %s\n",
			p.PID,
			p.PPID,
			p.CPU,
			memory,
			stateName(p.State),
			formatDuration(
				m.ticksDuration(p.Ticks),
			),
			p.Cmd,
		)
	}

	fmt.Println(strings.Repeat("-", 100))

	fmt.Printf(
		"Displayed %d/%d entries | CPU sum %.1f%% | process RSS sum %.1f MB\n",
		limit,
		len(processes),
		cpuTotal,
		bytesToMB(rssTotal),
	)
}

func (m *Monitor) renderTree(
	processes []Process,
) {
	procOnly := make(
		[]Process,
		0,
		len(processes),
	)

	for _, p := range processes {
		if p.Kind == processKind {
			procOnly = append(procOnly, p)
		}
	}

	if len(procOnly) == 0 {
		fmt.Println(
			"No processes available for tree view.",
		)
		return
	}

	byPID := make(
		map[int]Process,
		len(procOnly),
	)

	children := make(
		map[int][]Process,
	)

	for _, p := range procOnly {
		byPID[p.PID] = p

		children[p.PPID] = append(
			children[p.PPID],
			p,
		)
	}

	for parent := range children {
		sort.Slice(
			children[parent],
			func(i, j int) bool {
				return children[parent][i].PID <
					children[parent][j].PID
			},
		)
	}

	roots := make([]Process, 0)

	for _, p := range procOnly {
		if p.PPID <= 0 {
			roots = append(roots, p)
			continue
		}

		if _, ok := byPID[p.PPID]; !ok {
			roots = append(roots, p)
		}
	}

	sort.Slice(
		roots,
		func(i, j int) bool {
			return roots[i].PID <
				roots[j].PID
		},
	)

	fmt.Printf(
		"%-8s %-7s %-10s %-7s %s\n",
		"PID",
		"CPU%",
		"RSS(MB)",
		"STATE",
		"COMMAND",
	)

	fmt.Println(strings.Repeat("-", 100))

	printed := make(map[int]bool)
	count := 0

	for i, root := range roots {
		if count >= m.config.Limit {
			break
		}

		last := i == len(roots)-1

		m.printTreeNode(
			root,
			children,
			"",
			last,
			0,
			printed,
			&count,
		)
	}

	fmt.Println(strings.Repeat("-", 100))

	fmt.Printf(
		"Displayed %d/%d processes in tree view\n",
		minInt(count, m.config.Limit),
		len(procOnly),
	)
}

func (m *Monitor) printTreeNode(
	p Process,
	children map[int][]Process,
	prefix string,
	last bool,
	depth int,
	printed map[int]bool,
	total *int,
) {
	if depth > maxTreeDepth ||
		printed[p.PID] ||
		*total >= m.config.Limit {
		return
	}

	printed[p.PID] = true

	branch := ""

	if depth > 0 {
		if last {
			branch = "└─ "
		} else {
			branch = "├─ "
		}
	}

	fmt.Printf(
		"%-8d %-7.1f %-10.1f %-7s %s%s%s\n",
		p.PID,
		p.CPU,
		p.MemoryMB,
		stateName(p.State),
		prefix,
		branch,
		p.Cmd,
	)

	*total++

	nextPrefix := prefix

	if depth > 0 {
		if last {
			nextPrefix += "   "
		} else {
			nextPrefix += "│  "
		}
	}

	kids := children[p.PID]

	for i, child := range kids {
		if *total >= m.config.Limit {
			break
		}

		m.printTreeNode(
			child,
			children,
			nextPrefix,
			i == len(kids)-1,
			depth+1,
			printed,
			total,
		)
	}
}

func stateName(state byte) string {
	switch state {
	case 'R':
		return "RUN"

	case 'S':
		return "SLEEP"

	case 'D':
		return "DISK"

	case 'Z':
		return "ZOMBIE"

	case 'T', 't':
		return "STOP"

	case 'I':
		return "IDLE"

	case 'X', 'x':
		return "DEAD"

	case 'K':
		return "WAKE"

	case 'W':
		return "PAGE"

	case 'P':
		return "PARK"

	default:
		return string(state)
	}
}

func formatDuration(d time.Duration) string {
	if d < 0 {
		d = 0
	}

	total := int64(d / time.Second)

	days := total / 86400
	total %= 86400

	hours := total / 3600
	total %= 3600

	minutes := total / 60
	seconds := total % 60

	if days > 0 {
		return fmt.Sprintf(
			"%dd%02dh%02dm",
			days,
			hours,
			minutes,
		)
	}

	if hours > 0 {
		return fmt.Sprintf(
			"%02d:%02d:%02d",
			hours,
			minutes,
			seconds,
		)
	}

	return fmt.Sprintf(
		"%02d:%02d",
		minutes,
		seconds,
	)
}

func minInt(a, b int) int {
	if a < b {
		return a
	}

	return b
}

func readProcessIO(path string) (uint64, uint64) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, 0
	}
	var r, w uint64
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) != 2 {
			continue
		}
		n, err := strconv.ParseUint(f[1], 10, 64)
		if err != nil {
			continue
		}
		switch f[0] {
		case "read_bytes:":
			r = n
		case "write_bytes:":
			w = n
		}
	}
	return r, w
}

func readFDCount(path string) int {
	f, err := os.Open(path)
	if err != nil {
		return -1
	}
	defer f.Close()
	count := 0
	for {
		names, err := f.Readdirnames(256)
		count += len(names)
		if err == io.EOF {
			break
		}
		if err != nil {
			return -1
		}
	}
	return count
}

func readCgroup(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) == 3 && parts[0] == "0" && parts[1] == "" {
			return parts[2]
		}
	}
	return ""
}

func systemdUnit(group string) string {
	parts := strings.Split(group, "/")
	for i := len(parts) - 1; i >= 0; i-- {
		p := parts[i]
		if strings.HasSuffix(p, ".service") || strings.HasSuffix(p, ".scope") || strings.HasSuffix(p, ".slice") {
			return p
		}
	}
	return "-"
}

func readPressure(name string) Pressure {
	data, err := os.ReadFile("/proc/pressure/" + name)
	if err != nil {
		return Pressure{}
	}
	var p Pressure
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		for _, v := range f[1:] {
			if !strings.HasPrefix(v, "avg10=") {
				continue
			}
			n, err := strconv.ParseFloat(strings.TrimPrefix(v, "avg10="), 64)
			if err != nil {
				continue
			}
			if f[0] == "some" {
				p.Some = n
				p.Available = true
			}
			if f[0] == "full" {
				p.Full = n
			}
		}
	}
	return p
}

func pressureString(p Pressure) string {
	if !p.Available {
		return "N/A"
	}
	return fmt.Sprintf("some %.2f%% full %.2f%%", p.Some, p.Full)
}

func readSystemStats() SystemStats {
	st := SystemStats{CPU: readPressure("cpu"), Memory: readPressure("memory"), IO: readPressure("io")}
	data, err := os.ReadFile("/proc/meminfo")
	if err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			f := strings.Fields(line)
			if len(f) < 2 {
				continue
			}
			n, err := strconv.ParseUint(f[1], 10, 64)
			if err != nil {
				continue
			}
			n *= 1024
			switch f[0] {
			case "MemTotal:":
				st.MemTotal = n
			case "MemAvailable:":
				st.MemAvailable = n
			case "SwapTotal:":
				st.SwapTotal = n
			case "SwapFree:":
				st.SwapFree = n
			}
		}
	}
	data, err = os.ReadFile("/proc/loadavg")
	if err == nil {
		f := strings.Fields(string(data))
		if len(f) >= 3 {
			st.Load1, _ = strconv.ParseFloat(f[0], 64)
			st.Load5, _ = strconv.ParseFloat(f[1], 64)
			st.Load15, _ = strconv.ParseFloat(f[2], 64)
		}
	}
	return st
}

func (m *Monitor) renderJSON(s Snapshot) error {
	processes := append([]Process(nil), s.Processes...)
	m.sortProcesses(processes)
	if len(processes) > m.config.Limit {
		processes = processes[:m.config.Limit]
	}
	payload := struct {
		Timestamp     time.Time   `json:"timestamp"`
		UptimeSeconds float64     `json:"uptime_seconds"`
		Scanned       int         `json:"scanned"`
		Skipped       int         `json:"skipped"`
		System        SystemStats `json:"system"`
		Processes     []Process   `json:"processes"`
	}{s.TakenAt, s.Uptime.Seconds(), s.Scanned, s.Skipped, s.System, processes}
	return json.NewEncoder(os.Stdout).Encode(payload)
}
