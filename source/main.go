package main

import (
	"bufio"
	"flag"
	"fmt"
	"math"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode"
)

type Process struct {
	PID    int
	CPU    float64
	Memory float64
	Cmd    string
	State  string
	PPID   int
	Time   float64
	Type   string
}

type Config struct {
	Limit    int
	Sort     string
	Watch    bool
	Interval int
	Verbose  bool
	Zombie   bool
	Threads  bool
	Tree     bool
}

type ProcStat struct {
	uptime     float64
	hertz      float64
	config     Config
	procCount  int
	errorCount int
}

const (
	DefaultLimit    = 20
	DefaultInterval = 2
	DefaultHertz    = 100
	MinUptime       = 0.1
	MaxPIDScan      = 32768
	MaxCmdLength    = 80
)

func NewProcStat() *ProcStat {
	if runtime.GOOS != "linux" {
		fmt.Fprintf(os.Stderr, "Error: This tool only works on Linux systems\n")
		os.Exit(1)
	}

	ps := &ProcStat{}
	ps.validateProcFilesystem()
	ps.config = ps.parseArgs()
	ps.hertz = ps.detectHertz()
	ps.uptime = ps.getUptime()
	return ps
}

func (ps *ProcStat) validateProcFilesystem() {
	if _, err := os.Stat("/proc"); os.IsNotExist(err) {
		panic("'/proc' filesystem not available")
	}
	
	if _, err := os.Stat("/proc/self"); os.IsNotExist(err) {
		if _, err := os.Stat("/proc/version"); os.IsNotExist(err) {
			panic("'/proc' does not appear to be a valid proc filesystem")
		}
	}
}

func (ps *ProcStat) parseArgs() Config {
	config := Config{}

	flag.IntVar(&config.Limit, "limit", DefaultLimit, "Number of processes to show")
	flag.StringVar(&config.Sort, "sort", "cpu", "Sort by: cpu, mem, pid, time, command")
	flag.BoolVar(&config.Watch, "watch", false, "Enable watch mode")
	flag.IntVar(&config.Interval, "interval", DefaultInterval, "Refresh interval in seconds for watch mode")
	flag.BoolVar(&config.Verbose, "verbose", false, "Show verbose output")
	flag.BoolVar(&config.Zombie, "zombie", false, "Include zombie processes")
	flag.BoolVar(&config.Threads, "threads", false, "Show thread information")
	flag.BoolVar(&config.Tree, "tree", false, "Show process tree (implies --zombie)")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Process Monitor - Linux Process Statistics\n\n")
		fmt.Fprintf(os.Stderr, "Usage: %s [OPTIONS]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  %s -limit 10 -sort mem\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -watch -interval 5\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -threads -watch\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -tree -limit 30\n", os.Args[0])
	}

	flag.Parse()

	if config.Limit < 1 || config.Limit > 1000 {
		fmt.Fprintf(os.Stderr, "Warning: Limit %d out of range [1-1000], using default: %d\n", 
			config.Limit, DefaultLimit)
		config.Limit = DefaultLimit
	}
	
	if config.Interval < 1 || config.Interval > 3600 {
		fmt.Fprintf(os.Stderr, "Warning: Interval %d out of range [1-3600], using default: %d\n", 
			config.Interval, DefaultInterval)
		config.Interval = DefaultInterval
	}
	
	validSorts := map[string]bool{"cpu": true, "mem": true, "pid": true, "time": true, "command": true}
	if !validSorts[config.Sort] {
		fmt.Fprintf(os.Stderr, "Warning: Invalid sort '%s', using 'cpu'\n", config.Sort)
		config.Sort = "cpu"
	}
	
	if config.Tree {
		config.Zombie = true
	}

	return config
}

func (ps *ProcStat) validateProcPath(path string) bool {
	cleanPath := filepath.Clean(path)
	
	if !strings.HasPrefix(cleanPath, "/proc/") {
		return false
	}
	
	allowedPattern := regexp.MustCompile(`^/proc/(\d+|self)(/task/\d+)?(/stat|/status|/cmdline)?$`)
	return allowedPattern.MatchString(cleanPath)
}

func (ps *ProcStat) detectHertz() float64 {
	cmd := exec.Command("getconf", "CLK_TCK")
	output, err := cmd.Output()
	if err == nil {
		hzStr := strings.TrimSpace(string(output))
		if hz, err := strconv.ParseFloat(hzStr, 64); err == nil && hz > 0 {
			if ps.config.Verbose {
				fmt.Fprintf(os.Stderr, "Debug: Detected HERTZ: %.0f\n", hz)
			}
			return hz
		}
	}
	
	if ps.config.Verbose {
		fmt.Fprintf(os.Stderr, "Debug: Using default HERTZ value: %d\n", DefaultHertz)
	}
	return DefaultHertz
}

func (ps *ProcStat) getUptime() float64 {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		panic(fmt.Sprintf("Cannot read /proc/uptime: %v", err))
	}

	fields := strings.Fields(string(data))
	if len(fields) < 1 {
		panic("Invalid format in /proc/uptime")
	}

	uptime, err := strconv.ParseFloat(fields[0], 64)
	if err != nil || uptime <= 0 {
		panic("Invalid uptime value")
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
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	
	iteration := 0
	startTime := time.Now()
	
	go func() {
		for sig := range sigChan {
			duration := time.Since(startTime).Round(time.Second)
			fmt.Printf("\nMonitoring stopped after %v (signal: %v)\n", duration, sig)
			os.Exit(0)
		}
	}()
	
	fmt.Printf("Process Monitor - Refresh every %ds (Ctrl+C to stop)\n", ps.config.Interval)

	for {
		if iteration > 0 {
			fmt.Print("\033[2J\033[H")
		}
		
		ps.displayHeader(iteration)
		processes := ps.scanProcesses()
		ps.render(processes)
		
		time.Sleep(time.Duration(ps.config.Interval) * time.Second)
		iteration++
	}
}

func (ps *ProcStat) displayHeader(iteration int) {
	fmt.Printf("Process Monitor - Iteration #%d - %s\n", iteration+1, 
		time.Now().Format("2006-01-02 15:04:05"))
	fmt.Printf("Sorting by: %s | Showing top: %d | Refresh: %ds", 
		strings.ToUpper(ps.config.Sort), ps.config.Limit, ps.config.Interval)
	
	if ps.config.Zombie || ps.config.Threads || ps.config.Tree {
		modes := []string{}
		if ps.config.Zombie { modes = append(modes, "Zombies") }
		if ps.config.Threads { modes = append(modes, "Threads") }
		if ps.config.Tree { modes = append(modes, "Tree") }
		fmt.Printf(" | Modes: %s", strings.Join(modes, ", "))
	}
	fmt.Printf("\n%s\n\n", strings.Repeat("=", 80))
}

func (ps *ProcStat) scanProcesses() []Process {
	processes := make([]Process, 0, 500)
	ps.procCount = 0
	ps.errorCount = 0

	pidDirs, err := filepath.Glob("/proc/[0-9]*")
	if err != nil {
		if ps.config.Verbose {
			fmt.Fprintf(os.Stderr, "Error reading /proc: %v\n", err)
		}
		return processes
	}
	
	if len(pidDirs) > MaxPIDScan {
		panic(fmt.Sprintf("Too many processes to scan (%d), possible attack", len(pidDirs)))
	}

	for _, pidDir := range pidDirs {
		pidStr := filepath.Base(pidDir)
		pid, err := strconv.Atoi(pidStr)
		if err != nil {
			continue
		}
		
		ps.procCount++
		proc := ps.readProcess(pid)
		if proc != nil {
			processes = append(processes, *proc)
			
			if ps.config.Threads {
				threads := ps.readThreads(pid)
				processes = append(processes, threads...)
			}
		} else {
			ps.errorCount++
		}
	}

	if ps.config.Verbose && !ps.config.Watch {
		fmt.Fprintf(os.Stderr, "Debug: Scanned %d processes, %d errors\n", 
			ps.procCount, ps.errorCount)
	}

	return processes
}

func parseFloatField(field string) float64 {
	val, err := strconv.ParseFloat(field, 64)
	if err != nil {
		return 0
	}
	return val
}

func parseIntField(field string) int {
	val, err := strconv.ParseInt(field, 10, 32)
	if err != nil {
		return 0
	}
	return int(val)
}

func (ps *ProcStat) readProcess(pid int) *Process {
	statPath := fmt.Sprintf("/proc/%d/stat", pid)
	if !ps.validateProcPath(statPath) {
		return nil
	}

	statData, err := os.ReadFile(statPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		if ps.config.Verbose {
			fmt.Fprintf(os.Stderr, "Debug: Error reading %s: %v\n", statPath, err)
		}
		return nil
	}

	statStr := string(statData)
	
	if !ps.config.Zombie {
		if idx := strings.Index(statStr, ") Z "); idx != -1 {
			return nil
		}
	}

	start := strings.IndexRune(statStr, '(')
	end := strings.LastIndex(statStr, ")")
	if start == -1 || end == -1 {
		return nil
	}

	cmdName := statStr[start+1 : end]
	remaining := strings.Fields(statStr[end+2:])
	if len(remaining) < 22 {
		return nil
	}

	state := remaining[0]
	ppid := parseIntField(remaining[1])
	utime := parseFloatField(remaining[11])
	stime := parseFloatField(remaining[12])
	cutime := parseFloatField(remaining[13])
	cstime := parseFloatField(remaining[14])
	starttime := parseFloatField(remaining[19])

	totalTime := utime + stime + cutime + cstime
	seconds := ps.uptime - (starttime / ps.hertz)

	var cpu float64
	if seconds > MinUptime {
		cpu = 100 * ((totalTime / ps.hertz) / seconds)
		if cpu > 100 {
			cpu = 100
		}
	}

	memory := ps.getProcessMemory(pid)
	cmd := ps.getProcessCmd(pid, cmdName)

	return &Process{
		PID:    pid,
		CPU:    math.Round(cpu*10) / 10,
		Memory: math.Round(memory*10) / 10,
		Cmd:    cmd,
		State:  state,
		PPID:   ppid,
		Time:   totalTime / ps.hertz,
		Type:   "process",
	}
}

func (ps *ProcStat) readThreads(pid int) []Process {
	threads := make([]Process, 0)
	taskDir := fmt.Sprintf("/proc/%d/task", pid)
	
	taskEntries, err := os.ReadDir(taskDir)
	if err != nil {
		return threads
	}

	for _, taskEntry := range taskEntries {
		if !taskEntry.IsDir() {
			continue
		}

		tid, err := strconv.Atoi(taskEntry.Name())
		if err != nil || tid == pid {
			continue
		}

		if thread := ps.readThread(pid, tid); thread != nil {
			threads = append(threads, *thread)
		}
	}

	return threads
}

func (ps *ProcStat) readThread(pid, tid int) *Process {
	statPath := fmt.Sprintf("/proc/%d/task/%d/stat", pid, tid)
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
	if len(remaining) < 14 {
		return nil
	}

	state := remaining[0]
	utime := parseFloatField(remaining[11])
	stime := parseFloatField(remaining[12])

	totalTime := utime + stime
	var cpu float64
	if ps.uptime > MinUptime {
		cpu = 100 * ((totalTime / ps.hertz) / ps.uptime)
		if cpu > 100 {
			cpu = 100
		}
	}

	memory := ps.getProcessMemory(tid)
	cmd := "└─ " + sanitizeCmd(cmdName)

	return &Process{
		PID:    tid,
		CPU:    math.Round(cpu*10) / 10,
		Memory: math.Round(memory*10) / 10,
		Cmd:    cmd,
		State:  state,
		Time:   totalTime / ps.hertz,
		Type:   "thread",
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
	rss := 0.0
	vms := 0.0
	
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "VmRSS:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				if val, err := strconv.ParseFloat(fields[1], 64); err == nil {
					rss = val
				}
			}
		} else if strings.HasPrefix(line, "VmSize:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				if val, err := strconv.ParseFloat(fields[1], 64); err == nil {
					vms = val
				}
			}
		}
	}
	
	if rss > 0 {
		return rss / 1024
	}
	
	return vms / 1024
}

func sanitizeCmd(cmd string) string {
	var result strings.Builder
	result.Grow(len(cmd))
	
	for _, r := range cmd {
		if unicode.IsPrint(r) || r == '\t' || r == '\n' {
			result.WriteRune(r)
		} else {
			result.WriteRune('?')
		}
	}
	
	return strings.TrimSpace(result.String())
}

func (ps *ProcStat) getProcessCmd(pid int, fallback string) string {
	cmdlinePath := fmt.Sprintf("/proc/%d/cmdline", pid)
	if !ps.validateProcPath(cmdlinePath) {
		return "[" + sanitizeCmd(fallback) + "]"
	}

	cmdline, err := os.ReadFile(cmdlinePath)
	if err != nil || len(cmdline) == 0 {
		return "[" + sanitizeCmd(fallback) + "]"
	}

	cmd := strings.ReplaceAll(string(cmdline), "\x00", " ")
	cmd = sanitizeCmd(cmd)

	if cmd == "" {
		return "[" + sanitizeCmd(fallback) + "]"
	}

	if len(cmd) > MaxCmdLength {
		cmd = cmd[:MaxCmdLength-3] + "..."
	}
	return cmd
}

func (ps *ProcStat) buildProcessTree(processes []Process) map[int][]Process {
	tree := make(map[int][]Process)
	for _, proc := range processes {
		if proc.PPID > 0 {
			tree[proc.PPID] = append(tree[proc.PPID], proc)
		}
	}
	
	for ppid := range tree {
		sort.Slice(tree[ppid], func(i, j int) bool {
			return tree[ppid][i].PID < tree[ppid][j].PID
		})
	}
	
	return tree
}

func (ps *ProcStat) printTree(process Process, tree map[int][]Process, prefix string, depth int, printed map[int]bool) {
	if printed[process.PID] {
		return
	}
	printed[process.PID] = true
	
	fmt.Printf("%s", prefix)
	if depth > 0 {
		fmt.Printf("└─ ")
	}
	
	fmt.Printf("%-6d %-6.1f %-10.1f %-6s %s\n", 
		process.PID, process.CPU, process.Memory, process.State, process.Cmd)
	
	children := tree[process.PID]
	for i, child := range children {
		childPrefix := prefix
		if depth > 0 {
			if i == len(children)-1 {
				childPrefix += "    "
			} else {
				childPrefix += "│   "
			}
		}
		ps.printTree(child, tree, childPrefix, depth+1, printed)
	}
}

func (ps *ProcStat) render(processes []Process) {
	if len(processes) == 0 {
		fmt.Println("No processes found or insufficient permissions.")
		return
	}

	switch ps.config.Sort {
	case "mem":
		sort.Slice(processes, func(i, j int) bool {
			if processes[i].Memory == processes[j].Memory {
				return processes[i].PID < processes[j].PID
			}
			return processes[i].Memory > processes[j].Memory
		})
	case "pid":
		sort.Slice(processes, func(i, j int) bool {
			return processes[i].PID < processes[j].PID
		})
	case "time":
		sort.Slice(processes, func(i, j int) bool {
			if processes[i].Time == processes[j].Time {
				return processes[i].PID < processes[j].PID
			}
			return processes[i].Time > processes[j].Time
		})
	case "command":
		sort.Slice(processes, func(i, j int) bool {
			return strings.Compare(processes[i].Cmd, processes[j].Cmd) < 0
		})
	default:
		sort.Slice(processes, func(i, j int) bool {
			if processes[i].CPU == processes[j].CPU {
				return processes[i].PID < processes[j].PID
			}
			return processes[i].CPU > processes[j].CPU
		})
	}

	limit := ps.config.Limit
	if limit > len(processes) {
		limit = len(processes)
	}

	displayProcesses := processes[:limit]

	if ps.config.Tree {
		tree := ps.buildProcessTree(displayProcesses)
		printed := make(map[int]bool)
		
		fmt.Printf("%-6s %-6s %-10s %-6s %s\n", "PID", "CPU%", "MEM(MB)", "STATE", "COMMAND")
		fmt.Println(strings.Repeat("-", 80))
		
		rootProcesses := make([]Process, 0)
		for _, proc := range displayProcesses {
			if proc.PPID == 0 || !ps.processExists(proc.PPID, displayProcesses) {
				rootProcesses = append(rootProcesses, proc)
			}
		}
		
		for _, root := range rootProcesses {
			ps.printTree(root, tree, "", 0, printed)
		}
		
		if !ps.config.Watch {
			fmt.Println(strings.Repeat("-", 80))
			fmt.Printf("Showing %d processes in tree view\n", len(displayProcesses))
		}
	} else {
		fmt.Printf("%-6s %-6s %-10s %-6s %s\n", "PID", "CPU%", "MEM(MB)", "STATE", "COMMAND")
		fmt.Println(strings.Repeat("-", 80))
		
		for _, proc := range displayProcesses {
			pidDisplay := fmt.Sprintf("%d", proc.PID)
			if ps.config.Threads && proc.Type == "thread" {
				pidDisplay = "  " + pidDisplay
			}
			fmt.Printf("%-6s %-6.1f %-10.1f %-6s %s\n", 
				pidDisplay, proc.CPU, proc.Memory, proc.State, proc.Cmd)
		}
		
		if !ps.config.Watch {
			totalMemory := 0.0
			totalCPU := 0.0
			for _, proc := range displayProcesses {
				totalMemory += proc.Memory
				totalCPU += proc.CPU
			}
			fmt.Println(strings.Repeat("-", 80))
			fmt.Printf("Top %d processes: %.1f%% CPU, %.1f MB MEM", 
				len(displayProcesses), totalCPU, totalMemory)
			if ps.config.Zombie && ps.errorCount > 0 {
				fmt.Printf(" | %d errors", ps.errorCount)
			}
			fmt.Printf("\n")
		}
	}
}

func (ps *ProcStat) processExists(pid int, processes []Process) bool {
	for _, proc := range processes {
		if proc.PID == pid {
			return true
		}
	}
	return false
}

func main() {
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", r)
			fmt.Fprintf(os.Stderr, "Try running with -help for usage information\n")
			os.Exit(1)
		}
	}()
	
	NewProcStat().Run()
}
