package main

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
)

type Process struct {
	PID    int
	CPU    float64
	Memory float64
	Cmd    string
}

type Config struct {
	Limit int
	Sort  string
}

type ProcStat struct {
	uptime float64
	hertz  float64
	config Config
}

func NewProcStat() *ProcStat {
	ps := &ProcStat{}
	ps.hertz = ps.detectHertz()
	ps.uptime = ps.getUptime()
	ps.config = ps.parseArgs()
	return ps
}

func (ps *ProcStat) parseArgs() Config {
	config := Config{Limit: 20, Sort: "cpu"}
	
	for i := 1; i < len(os.Args); i++ {
		switch os.Args[i] {
		case "--limit":
			if i+1 < len(os.Args) {
				if limit, err := strconv.Atoi(os.Args[i+1]); err == nil && limit > 0 {
					config.Limit = limit
				}
				i++
			}
		case "--sort":
			if i+1 < len(os.Args) {
				sortKey := os.Args[i+1]
				if sortKey == "cpu" || sortKey == "mem" || sortKey == "pid" {
					config.Sort = sortKey
				}
				i++
			}
		}
	}
	return config
}

func (ps *ProcStat) detectHertz() float64 {
	output, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err == nil && strings.Contains(string(output), "HZ=250") {
		return 250
	}
	return 100
}

func (ps *ProcStat) getUptime() float64 {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0.1
	}
	fields := strings.Fields(string(data))
	if len(fields) < 1 {
		return 0.1
	}
	uptime, _ := strconv.ParseFloat(fields[0], 64)
	return uptime
}

func (ps *ProcStat) Run() {
	processes := ps.scanProcesses()
	ps.render(processes)
}

func (ps *ProcStat) scanProcesses() []Process {
	var processes []Process
	
	entries, err := os.ReadDir("/proc")
	if err != nil {
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
	return processes
}

func (ps *ProcStat) readProcess(pid int) *Process {
	statData, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
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

	utime, _ := strconv.ParseFloat(remaining[11], 64)
	stime, _ := strconv.ParseFloat(remaining[12], 64)
	cutime, _ := strconv.ParseFloat(remaining[13], 64)
	cstime, _ := strconv.ParseFloat(remaining[14], 64)
	starttime, _ := strconv.ParseFloat(remaining[19], 64)

	totalTime := utime + stime + cutime + cstime
	seconds := ps.uptime - (starttime / ps.hertz)
	
	var cpu float64
	if seconds > 0 {
		cpu = 100 * ((totalTime / ps.hertz) / seconds)
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
	file, err := os.Open(fmt.Sprintf("/proc/%d/status", pid))
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
				memKB, _ := strconv.ParseFloat(fields[1], 64)
				return memKB / 1024
			}
		}
	}
	return 0
}

func (ps *ProcStat) getProcessCmd(pid int, fallback string) string {
	cmdline, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return "[" + fallback + "]"
	}

	if len(cmdline) == 0 {
		return "[" + fallback + "]"
	}

	cmd := strings.ReplaceAll(string(cmdline), "\x00", " ")
	cmd = strings.TrimSpace(cmd)
	
	if len(cmd) > 80 {
		cmd = cmd[:77] + "..."
	}
	return cmd
}

func (ps *ProcStat) render(processes []Process) {
	sort.Slice(processes, func(i, j int) bool {
		switch ps.config.Sort {
		case "mem":
			return processes[i].Memory > processes[j].Memory
		case "pid":
			return processes[i].PID > processes[j].PID
		default:
			return processes[i].CPU > processes[j].CPU
		}
	})

	limit := ps.config.Limit
	if limit > len(processes) {
		limit = len(processes)
	}

	fmt.Printf("%5s %6s %9s %s\n", "PID", "CPU%", "MEM(MB)", "CMD")
	for _, proc := range processes[:limit] {
		fmt.Printf("%5d %6.1f %9.1f %s\n", proc.PID, proc.CPU, proc.Memory, proc.Cmd)
	}
}

func main() {
	NewProcStat().Run()
}
