package usermgr

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/hnrobert/lumgr/internal/hostfs"
)

type PasswdFile struct {
	pf parsedFile[PasswdEntry]
}

func LoadPasswd(path string) (*PasswdFile, error) {
	b, err := hostfs.ReadFile(path)
	if err != nil {
		return nil, err
	}
	lines, err := readLines(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}

	var pf parsedFile[PasswdEntry]
	for _, line := range lines {
		trim := strings.TrimSpace(line)
		if trim == "" || strings.HasPrefix(trim, "#") {
			pf.lines = append(pf.lines, rawLine[PasswdEntry]{raw: line})
			continue
		}
		parts := parseColonLine(line)
		if len(parts) < 7 {
			// Preserve unknown line as-is.
			pf.lines = append(pf.lines, rawLine[PasswdEntry]{raw: line})
			continue
		}
		uid, err := atoi(parts[2], "passwd.uid")
		if err != nil {
			return nil, err
		}
		gid, err := atoi(parts[3], "passwd.gid")
		if err != nil {
			return nil, err
		}
		e := PasswdEntry{
			Name:   parts[0],
			Passwd: parts[1],
			UID:    uid,
			GID:    gid,
			Gecos:  parts[4],
			Home:   parts[5],
			Shell:  parts[6],
		}
		pf.lines = append(pf.lines, rawLine[PasswdEntry]{entry: &e})
	}

	return &PasswdFile{pf: pf}, nil
}

func (f *PasswdFile) Find(name string) *PasswdEntry {
	for _, e := range f.pf.entries() {
		if e.Name == name {
			return e
		}
	}
	return nil
}

func (f *PasswdFile) List() []PasswdEntry {
	out := make([]PasswdEntry, 0)
	for _, e := range f.pf.entries() {
		out = append(out, *e)
	}
	return out
}

func (f *PasswdFile) Delete(name string) bool {
	changed := false
	for i := range f.pf.lines {
		e := f.pf.lines[i].entry
		if e != nil && e.Name == name {
			f.pf.lines[i].entry = nil
			f.pf.lines[i].raw = ""
			changed = true
		}
	}
	if !changed {
		return false
	}
	// Compact removed lines.
	var nl []rawLine[PasswdEntry]
	for _, ln := range f.pf.lines {
		if ln.entry == nil && ln.raw == "" {
			continue
		}
		nl = append(nl, ln)
	}
	f.pf.lines = nl
	return true
}

func (f *PasswdFile) Add(e PasswdEntry) error {
	if f.Find(e.Name) != nil {
		return fmt.Errorf("user already exists: %s", e.Name)
	}
	f.pf.lines = append(f.pf.lines, rawLine[PasswdEntry]{entry: &e})
	return nil
}

func (f *PasswdFile) NextUID(min int) int {
	max := min - 1
	for _, e := range f.pf.entries() {
		if e.UID > max {
			max = e.UID
		}
	}
	return max + 1
}

func (f *PasswdFile) Bytes() []byte {
	var buf strings.Builder
	for _, ln := range f.pf.lines {
		if ln.entry != nil {
			e := ln.entry
			buf.WriteString(fmt.Sprintf("%s:%s:%d:%d:%s:%s:%s\n",
				e.Name, e.Passwd, e.UID, e.GID, e.Gecos, e.Home, e.Shell))
			continue
		}
		buf.WriteString(ln.raw)
		buf.WriteString("\n")
	}
	return []byte(buf.String())
}
