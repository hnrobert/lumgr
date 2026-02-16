package resmon

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

type cpuSnapshot struct {
	user   uint64
	nice   uint64
	system uint64
	idle   uint64
	iowait uint64
	irq    uint64
	soft   uint64
	steal  uint64
}

func (c cpuSnapshot) total() uint64 {
	return c.user + c.nice + c.system + c.idle + c.iowait + c.irq + c.soft + c.steal
}

type userAgg struct {
	cpuTicks uint64
	memBytes uint64
	procs    int
}

type Collector struct {
	procRoot string

	mu            sync.Mutex
	prevCPU       *cpuSnapshot
	prevDiskRead  uint64
	prevDiskWrite uint64
	prevNetRx     uint64
	prevNetTx     uint64
	hasPrevDisk   bool
	hasPrevNet    bool
}

func NewCollector(procRoot string) *Collector {
	if strings.TrimSpace(procRoot) == "" {
		procRoot = "/proc"
	}
	return &Collector{procRoot: procRoot}
}

func (c *Collector) Collect(cfg Config) (Metrics, []UserResource, error) {
	cfg = cfg.WithDefaults()
	m := Metrics{Timestamp: time.Now().UTC()}

	if cfg.CollectCPU {
		cpu, err := c.readCPU()
		if err != nil {
			return m, nil, err
		}
		m.CPUUser = cpu.CPUUser
		m.CPUSystem = cpu.CPUSystem
		m.CPUIdle = cpu.CPUIdle
		m.CPUUsage = cpu.CPUUsage
	}

	if cfg.CollectMemory {
		total, used, avail, err := c.readMemInfo()
		if err != nil {
			return m, nil, err
		}
		m.MemTotal = total
		m.MemUsed = used
		m.MemAvailable = avail
	}

	if cfg.CollectDiskIO {
		r, w, err := c.readDiskStats()
		if err != nil {
			return m, nil, err
		}
		m.DiskReadBytes = r
		m.DiskWriteBytes = w
	}

	if cfg.CollectFilesystem {
		fs, err := c.readFilesystems()
		if err != nil {
			return m, nil, err
		}
		m.Filesystems = fs
	}

	if cfg.CollectNetwork {
		rx, tx, err := c.readNetwork()
		if err != nil {
			return m, nil, err
		}
		m.NetworkRxBytes = rx
		m.NetworkTxBytes = tx
	}

	var users []UserResource
	if cfg.CollectUserStats {
		u, err := c.readUserProcesses()
		if err != nil {
			return m, nil, err
		}
		users = u
	}

	return m, users, nil
}

func (c *Collector) readCPU() (Metrics, error) {
	p := filepath.Join(c.procRoot, "stat")
	f, err := os.Open(p)
	if err != nil {
		return Metrics{}, err
	}
	defer f.Close()

	s := bufio.NewScanner(f)
	if !s.Scan() {
		if s.Err() != nil {
			return Metrics{}, s.Err()
		}
		return Metrics{}, fmt.Errorf("empty /proc/stat")
	}
	line := strings.Fields(s.Text())
	if len(line) < 8 || line[0] != "cpu" {
		return Metrics{}, fmt.Errorf("invalid /proc/stat cpu line")
	}
	parse := func(v string) uint64 {
		n, _ := strconv.ParseUint(v, 10, 64)
		return n
	}
	now := &cpuSnapshot{
		user:   parse(line[1]),
		nice:   parse(line[2]),
		system: parse(line[3]),
		idle:   parse(line[4]),
		iowait: parse(line[5]),
		irq:    parse(line[6]),
		soft:   parse(line[7]),
	}
	if len(line) > 8 {
		now.steal = parse(line[8])
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.prevCPU == nil {
		c.prevCPU = now
		return Metrics{CPUIdle: 100}, nil
	}
	prev := c.prevCPU
	c.prevCPU = now

	totalDelta := float64(now.total() - prev.total())
	if totalDelta <= 0 {
		return Metrics{CPUIdle: 100}, nil
	}
	userDelta := float64((now.user + now.nice) - (prev.user + prev.nice))
	sysDelta := float64((now.system + now.irq + now.soft) - (prev.system + prev.irq + prev.soft))
	idleDelta := float64((now.idle + now.iowait) - (prev.idle + prev.iowait))

	cpuUser := (userDelta / totalDelta) * 100
	cpuSystem := (sysDelta / totalDelta) * 100
	cpuIdle := (idleDelta / totalDelta) * 100
	usage := 100 - cpuIdle
	if usage < 0 {
		usage = 0
	}
	return Metrics{
		CPUUser:   cpuUser,
		CPUSystem: cpuSystem,
		CPUIdle:   cpuIdle,
		CPUUsage:  usage,
	}, nil
}

func (c *Collector) readMemInfo() (total, used, available uint64, err error) {
	p := filepath.Join(c.procRoot, "meminfo")
	b, err := os.ReadFile(p)
	if err != nil {
		return 0, 0, 0, err
	}
	var memTotal, memAvail, memFree, buffers, cached uint64
	for _, ln := range strings.Split(string(b), "\n") {
		f := strings.Fields(ln)
		if len(f) < 2 {
			continue
		}
		v, _ := strconv.ParseUint(f[1], 10, 64)
		mul := uint64(1)
		if len(f) >= 3 {
			switch strings.ToLower(strings.TrimSpace(f[2])) {
			case "kb", "kib":
				mul = 1024
			case "mb", "mib":
				mul = 1024 * 1024
			case "gb", "gib":
				mul = 1024 * 1024 * 1024
			}
		}
		v *= mul
		switch strings.TrimSuffix(f[0], ":") {
		case "MemTotal":
			memTotal = v
		case "MemAvailable":
			memAvail = v
		case "MemFree":
			memFree = v
		case "Buffers":
			buffers = v
		case "Cached":
			cached = v
		}
	}
	if memAvail == 0 {
		memAvail = memFree + buffers + cached
	}
	memUsed := uint64(0)
	if memTotal > memAvail {
		memUsed = memTotal - memAvail
	}
	return memTotal, memUsed, memAvail, nil
}

func (c *Collector) readDiskStats() (readBytes, writeBytes uint64, err error) {
	p := filepath.Join(c.procRoot, "diskstats")
	b, err := os.ReadFile(p)
	if err != nil {
		return 0, 0, err
	}
	var totalRead, totalWrite uint64
	for _, ln := range strings.Split(string(b), "\n") {
		f := strings.Fields(ln)
		if len(f) < 14 {
			continue
		}
		name := f[2]
		if strings.HasPrefix(name, "loop") || strings.HasPrefix(name, "ram") {
			continue
		}
		readSectors, _ := strconv.ParseUint(f[5], 10, 64)
		writeSectors, _ := strconv.ParseUint(f[9], 10, 64)
		totalRead += readSectors * 512
		totalWrite += writeSectors * 512
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.hasPrevDisk {
		c.prevDiskRead = totalRead
		c.prevDiskWrite = totalWrite
		c.hasPrevDisk = true
		return 0, 0, nil
	}
	if totalRead >= c.prevDiskRead {
		readBytes = totalRead - c.prevDiskRead
	}
	if totalWrite >= c.prevDiskWrite {
		writeBytes = totalWrite - c.prevDiskWrite
	}
	c.prevDiskRead = totalRead
	c.prevDiskWrite = totalWrite
	return readBytes, writeBytes, nil
}

func (c *Collector) readFilesystems() ([]FSInfo, error) {
	p := filepath.Join(c.procRoot, "mounts")
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	skipFs := map[string]bool{
		"proc": true, "sysfs": true, "devtmpfs": true, "devpts": true,
		"tmpfs": true, "cgroup": true, "cgroup2": true, "overlay": true,
		"squashfs": true, "mqueue": true,
	}
	seen := map[string]bool{}
	var out []FSInfo
	for _, ln := range strings.Split(string(b), "\n") {
		f := strings.Fields(ln)
		if len(f) < 3 {
			continue
		}
		mnt := f[1]
		fst := f[2]
		if skipFs[fst] || seen[mnt] {
			continue
		}
		fi, err := os.Stat(mnt)
		if err != nil || !fi.IsDir() {
			continue
		}
		seen[mnt] = true
		var s syscall.Statfs_t
		if err := syscall.Statfs(mnt, &s); err != nil {
			continue
		}
		blockSize := uint64(s.Bsize)
		if v := reflect.ValueOf(s).FieldByName("Frsize"); v.IsValid() {
			switch v.Kind() {
			case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
				if vv := v.Int(); vv > 0 {
					blockSize = uint64(vv)
				}
			case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
				if vv := v.Uint(); vv > 0 {
					blockSize = vv
				}
			}
		}
		total := s.Blocks * blockSize
		avail := s.Bavail * blockSize
		used := uint64(0)
		if total > avail {
			used = total - avail
		}
		pct := 0.0
		if total > 0 {
			pct = (float64(used) / float64(total)) * 100
		}
		out = append(out, FSInfo{MountPoint: mnt, Total: total, Used: used, UsePercent: pct})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].MountPoint < out[j].MountPoint })
	return out, nil
}

func (c *Collector) readNetwork() (rx, tx uint64, err error) {
	p := filepath.Join(c.procRoot, "net", "dev")
	b, err := os.ReadFile(p)
	if err != nil {
		return 0, 0, err
	}
	var totalRx, totalTx uint64
	for _, ln := range strings.Split(string(b), "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" || strings.HasPrefix(ln, "Inter-") || strings.HasPrefix(ln, "face") {
			continue
		}
		parts := strings.Split(ln, ":")
		if len(parts) != 2 {
			continue
		}
		iface := strings.TrimSpace(parts[0])
		if iface == "lo" {
			continue
		}
		f := strings.Fields(parts[1])
		if len(f) < 16 {
			continue
		}
		rxb, _ := strconv.ParseUint(f[0], 10, 64)
		txb, _ := strconv.ParseUint(f[8], 10, 64)
		totalRx += rxb
		totalTx += txb
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.hasPrevNet {
		c.prevNetRx = totalRx
		c.prevNetTx = totalTx
		c.hasPrevNet = true
		return 0, 0, nil
	}
	if totalRx >= c.prevNetRx {
		rx = totalRx - c.prevNetRx
	}
	if totalTx >= c.prevNetTx {
		tx = totalTx - c.prevNetTx
	}
	c.prevNetRx = totalRx
	c.prevNetTx = totalTx
	return rx, tx, nil
}

func readPasswdMap() map[string]string {
	m := map[string]string{}
	b, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return m
	}
	for _, ln := range strings.Split(string(b), "\n") {
		if ln == "" || strings.HasPrefix(ln, "#") {
			continue
		}
		f := strings.Split(ln, ":")
		if len(f) < 3 {
			continue
		}
		m[f[2]] = f[0]
	}
	return m
}

func (c *Collector) readUserProcesses() ([]UserResource, error) {
	ents, err := os.ReadDir(c.procRoot)
	if err != nil {
		return nil, err
	}
	uidToUser := readPasswdMap()
	agg := map[string]*userAgg{}
	for _, ent := range ents {
		if !ent.IsDir() {
			continue
		}
		pid := ent.Name()
		if _, err := strconv.Atoi(pid); err != nil {
			continue
		}
		statusPath := filepath.Join(c.procRoot, pid, "status")
		statPath := filepath.Join(c.procRoot, pid, "stat")
		b, err := os.ReadFile(statusPath)
		if err != nil {
			continue
		}
		uid := ""
		vmrss := uint64(0)
		for _, ln := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(ln, "Uid:") {
				f := strings.Fields(ln)
				if len(f) >= 2 {
					uid = f[1]
				}
			}
			if strings.HasPrefix(ln, "VmRSS:") {
				f := strings.Fields(ln)
				if len(f) >= 2 {
					v, _ := strconv.ParseUint(f[1], 10, 64)
					vmrss = v * 1024
				}
			}
		}
		if uid == "" {
			continue
		}
		uidNum, err := strconv.Atoi(uid)
		if err == nil && uidNum > 0 && uidNum < 1000 {
			continue
		}
		user := uidToUser[uid]
		if user == "" {
			user = "uid:" + uid
		}
		pb, err := os.ReadFile(statPath)
		if err != nil {
			continue
		}
		fields := strings.Fields(string(pb))
		if len(fields) < 15 {
			continue
		}
		utime, _ := strconv.ParseUint(fields[13], 10, 64)
		stime, _ := strconv.ParseUint(fields[14], 10, 64)
		ua := agg[user]
		if ua == nil {
			ua = &userAgg{}
			agg[user] = ua
		}
		ua.cpuTicks += utime + stime
		ua.memBytes += vmrss
		ua.procs++
	}

	var totalTicks uint64
	for _, v := range agg {
		totalTicks += v.cpuTicks
	}

	out := make([]UserResource, 0, len(agg))
	for user, v := range agg {
		cpu := 0.0
		if totalTicks > 0 {
			cpu = (float64(v.cpuTicks) / float64(totalTicks)) * 100
		}
		out = append(out, UserResource{Username: user, CPU: cpu, MemoryBytes: v.memBytes, ProcessCount: v.procs})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CPU == out[j].CPU {
			return out[i].MemoryBytes > out[j].MemoryBytes
		}
		return out[i].CPU > out[j].CPU
	})
	if len(out) > 20 {
		out = out[:20]
	}
	return out, nil
}
