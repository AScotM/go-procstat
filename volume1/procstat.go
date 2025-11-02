package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

type Process struct {
	PID    int
	CPU    float64
	Memory float64
	Cmd    string
}

type Config struct {
	Limit    int
	Sort     string
	Watch    bool
	Interval int
	Verbose  bool
}

type ProcStat struct {
	uptime float64
	hertz  float64
	config Config
}

func NewProcStat() *ProcStat {
	ps := &ProcStat{}
	ps.config = ps.parseArgs()
	ps.hertz = ps.detectHertz()
	ps.uptime = ps.getUptime()
	return ps
}

func (ps *ProcStat) parseArgs() Config {
	config := Config{}

	flag.IntVar(&config.Limit, "limit", 20, "Number of processes to show")
	flag.StringVar(&config.Sort, "sort", "cpu", "Sort by: cpu, mem, pid")
	flag.BoolVar(&config.Watch, "watch", false, "Enable watch mode")
	flag.IntVar(&config.Interval, "interval", 2, "Refresh interval in seconds for watch mode")
	flag.BoolVar(&config.Verbose, "verbose", false, "Show verbose output")
	
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [OPTIONS]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  %s -limit 10 -sort mem\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -watch -interval 5\n", os.Args[0])
	}

	flag.Parse()

	// Validate configuration
	if config.Limit < 1 || config.Limit > 1000 {
		config.Limit = 20
	}
	if config.Sort != "cpu" && config.Sort != "mem" && config.Sort != "pid" {
		config.Sort = "cpu"
	}
	if config.Interval < 1 {
		config.Interval = 2
	}

	return config
}

func (ps *ProcStat) validateProcPath(path string) bool {
	cleaned := filepath.Clean(path)
	return strings.HasPrefix(cleaned, "/proc/") && !strings.Contains(cleaned, "/../")
}

func (ps *ProcStat) detectHertz() float64 {
	// In Go, we could use syscall.Sysconf(syscall.SC_CLK_TCK) but it's simpler to use 100
	return 100
}

func (ps *ProcStat) getUptime() float64 {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		if ps.config.Verbose {
			fmt.Fprintf(os.Stderr, "Warning: Cannot read /proc/uptime: %v\n", err)
		}
		return 0.1
	}

	fields := strings.Fields(string(data))
	if len(fields) < 1 {
		return 0.1
	}

	uptime, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return 0.1
	}

	if ps.config.Verbose {
		fmt.Fprintf(os.Stderr, "Debug: System uptime: %.2fs\n", uptime)
	}

	return uptime
}

func (ps *ProcStat) Run() {
	if ps.config.Watch {
		ps.runWatchMode()
	} else {
		processes := ps.scanProcesses()
		ps.render(processes)
	}
}

func (ps *ProcStat) runWatchMode() {
	iteration := 0
	for {
		if iteration > 0 {
			fmt.Print("\033[2J\033[H") // Clear screen
		}
		
		fmt.Printf("Process Monitor - Iteration #%d - %s\n", iteration+1, time.Now().Format("2006-01-02 15:04:05"))
		fmt.Printf("Sorting by: %s | Showing top: %d | Refresh: %ds\n\n", 
			strings.ToUpper(ps.config.Sort), ps.config.Limit, ps.config.Interval)
		
		processes := ps.scanProcesses()
		ps.render(processes)
		
		time.Sleep(time.Duration(ps.config.Interval) * time.Second)
		iteration++
	}
}

func (ps *ProcStat) scanProcesses() []Process {
	var processes []Process

	entries, err := os.ReadDir("/proc")
	if err != nil {
		if ps.config.Verbose {
			fmt.Fprintf(os.Stderr, "Error reading /proc: %v\n", err)
		}
		return processes
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}

		if proc := ps.readProcess(pid); proc != nil {
			processes = append(processes, *proc)
		}
	}

	if ps.config.Verbose && !ps.config.Watch {
		fmt.Fprintf(os.Stderr, "Debug: Scanned %d processes\n", len(processes))
	}

	return processes
}

func parseField(field string) float64 {
	val, err := strconv.ParseFloat(field, 64)
	if err != nil {
		return 0
	}
	return val
}

func (ps *ProcStat) readProcess(pid int) *Process {
	statPath := fmt.Sprintf("/proc/%d/stat", pid)
	if !ps.validateProcPath(statPath) {
		return nil
	}

	statData, err := os.ReadFile(statPath)
	if err != nil {
		return nil
	}

	statStr := string(statData)
	start := strings.IndexRune(statStr, '(')
	end := strings.LastIndex(statStr, ")")
	if start == -1 || end == -1 {
		return nil
	}

	cmdName := statStr[start+1 : end]
	remaining := strings.Fields(statStr[end+2:])
	if len(remaining) < 20 {
		return nil
	}

	utime := parseField(remaining[11])
	stime := parseField(remaining[12])
	cutime := parseField(remaining[13])
	cstime := parseField(remaining[14])
	starttime := parseField(remaining[19])

	totalTime := utime + stime + cutime + cstime
	seconds := ps.uptime - (starttime / ps.hertz)

	var cpu float64
	if seconds > 0 {
		cpu = 100 * ((totalTime / ps.hertz) / seconds)
		if cpu > 100 {
			cpu = 100 // Cap at 100%
		}
	}

	memory := ps.getProcessMemory(pid)
	cmd := ps.getProcessCmd(pid, cmdName)

	return &Process{
		PID:    pid,
		CPU:    cpu,
		Memory: memory,
		Cmd:    cmd,
	}
}

func (ps *ProcStat) getProcessMemory(pid int) float64 {
	statusPath := fmt.Sprintf("/proc/%d/status", pid)
	if !ps.validateProcPath(statusPath) {
		return 0
	}

	file, err := os.Open(statusPath)
	if err != nil {
		return 0
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "VmRSS:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				memKB, err := strconv.ParseFloat(fields[1], 64)
				if err == nil {
					return memKB / 1024 // Convert kB to MB
				}
			}
		}
	}
	return 0
}

func sanitizeCmd(cmd string) string {
	// Remove control characters
	cmd = strings.Map(func(r rune) rune {
		if r >= 32 || r == '\t' || r == '\n' {
			return r
		}
		return -1
	}, cmd)
	return strings.TrimSpace(cmd)
}

func (ps *ProcStat) getProcessCmd(pid int, fallback string) string {
	cmdlinePath := fmt.Sprintf("/proc/%d/cmdline", pid)
	if !ps.validateProcPath(cmdlinePath) {
		return "[" + fallback + "]"
	}

	cmdline, err := os.ReadFile(cmdlinePath)
	if err != nil || len(cmdline) == 0 {
		return "[" + fallback + "]"
	}

	cmd := strings.ReplaceAll(string(cmdline), "\x00", " ")
	cmd = sanitizeCmd(cmd)

	if cmd == "" {
		return "[" + fallback + "]"
	}

	// Truncate long commands
	if len(cmd) > 80 {
		cmd = cmd[:77] + "..."
	}
	return cmd
}

func (ps *ProcStat) render(processes []Process) {
	if len(processes) == 0 {
		fmt.Println("No processes found or insufficient permissions.")
		return
	}

	// Sort processes
	switch ps.config.Sort {
	case "mem":
		sort.Slice(processes, func(i, j int) bool {
			if processes[i].Memory == processes[j].Memory {
				return processes[i].PID > processes[j].PID
			}
			return processes[i].Memory > processes[j].Memory
		})
	case "pid":
		sort.Slice(processes, func(i, j int) bool {
			return processes[i].PID > processes[j].PID
		})
	default:
		sort.Slice(processes, func(i, j int) bool {
			if processes[i].CPU == processes[j].CPU {
				return processes[i].PID > processes[j].PID
			}
			return processes[i].CPU > processes[j].CPU
		})
	}

	limit := ps.config.Limit
	if limit > len(processes) {
		limit = len(processes)
	}

	fmt.Printf("%-6s %-6s %-10s %s\n", "PID", "CPU%", "MEM(MB)", "COMMAND")
	fmt.Println(strings.Repeat("-", 80))

	for _, proc := range processes[:limit] {
		fmt.Printf("%-6d %-6.1f %-10.1f %s\n", proc.PID, proc.CPU, proc.Memory, proc.Cmd)
	}

	// Show summary
	if !ps.config.Watch {
		totalMemory := 0.0
		totalCPU := 0.0
		for _, proc := range processes[:limit] {
			totalMemory += proc.Memory
			totalCPU += proc.CPU
		}
		fmt.Println(strings.Repeat("-", 80))
		fmt.Printf("Top %d processes: %.1f%% CPU, %.1f MB MEM\n", limit, totalCPU, totalMemory)
	}
}

func main() {
	NewProcStat().Run()
}
