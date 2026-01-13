package usermgr

import (
	"bytes"
	"fmt"
	"sort"
	"strings"

	"github.com/hnrobert/lumgr/internal/hostfs"
)

type GroupFile struct {
	pf parsedFile[GroupEntry]
}

func LoadGroup(path string) (*GroupFile, error) {
	b, err := hostfs.ReadFile(path)
	if err != nil {
		return nil, err
	}
	lines, err := readLines(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}

	var pf parsedFile[GroupEntry]
	for _, line := range lines {
		trim := strings.TrimSpace(line)
		if trim == "" || strings.HasPrefix(trim, "#") {
			pf.lines = append(pf.lines, rawLine[GroupEntry]{raw: line})
			continue
		}
		parts := parseColonLine(line)
		if len(parts) < 4 {
			pf.lines = append(pf.lines, rawLine[GroupEntry]{raw: line})
			continue
		}
		gid, err := atoi(parts[2], "group.gid")
		if err != nil {
			return nil, err
		}
		members := []string{}
		if parts[3] != "" {
			members = strings.Split(parts[3], ",")
		}
		e := GroupEntry{Name: parts[0], Passwd: parts[1], GID: gid, Members: members}
		pf.lines = append(pf.lines, rawLine[GroupEntry]{entry: &e})
	}
	return &GroupFile{pf: pf}, nil
}

func (f *GroupFile) Find(name string) *GroupEntry {
	for _, e := range f.pf.entries() {
		if e.Name == name {
			return e
		}
	}
	return nil
}

func (f *GroupFile) FindByGID(gid int) *GroupEntry {
	for _, e := range f.pf.entries() {
		if e.GID == gid {
			return e
		}
	}
	return nil
}

func (f *GroupFile) List() []GroupEntry {
	out := make([]GroupEntry, 0)
	for _, e := range f.pf.entries() {
		out = append(out, *e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].GID < out[j].GID })
	return out
}

func (f *GroupFile) Add(e GroupEntry) error {
	if f.Find(e.Name) != nil {
		return fmt.Errorf("group already exists: %s", e.Name)
	}
	if f.FindByGID(e.GID) != nil {
		return fmt.Errorf("gid already exists: %d", e.GID)
	}
	f.pf.lines = append(f.pf.lines, rawLine[GroupEntry]{entry: &e})
	return nil
}

func (f *GroupFile) Delete(name string) bool {
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
	var nl []rawLine[GroupEntry]
	for _, ln := range f.pf.lines {
		if ln.entry == nil && ln.raw == "" {
			continue
		}
		nl = append(nl, ln)
	}
	f.pf.lines = nl
	return true
}

func (f *GroupFile) NextGID(min int) int {
	max := min - 1
	for _, e := range f.pf.entries() {
		if e.GID > max {
			max = e.GID
		}
	}
	return max + 1
}

func (f *GroupFile) AddMember(group, user string) error {
	g := f.Find(group)
	if g == nil {
		return fmt.Errorf("group not found: %s", group)
	}
	for _, m := range g.Members {
		if m == user {
			return nil
		}
	}
	g.Members = append(g.Members, user)
	sort.Strings(g.Members)
	return nil
}

func (f *GroupFile) RemoveMemberEverywhere(user string) {
	for _, g := range f.pf.entries() {
		var out []string
		for _, m := range g.Members {
			if m != user {
				out = append(out, m)
			}
		}
		g.Members = out
	}
}

func (f *GroupFile) Bytes() []byte {
	var buf strings.Builder
	for _, ln := range f.pf.lines {
		if ln.entry != nil {
			e := ln.entry
			members := strings.Join(e.Members, ",")
			buf.WriteString(fmt.Sprintf("%s:%s:%d:%s\n", e.Name, e.Passwd, e.GID, members))
		} else {
			buf.WriteString(ln.raw)
			buf.WriteString("\n")
		}
	}
	return []byte(buf.String())
}
