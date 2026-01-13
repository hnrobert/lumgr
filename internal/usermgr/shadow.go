package usermgr

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/hnrobert/lumgr/internal/hostfs"
)

type ShadowFile struct {
	pf parsedFile[ShadowEntry]
}

func LoadShadow(path string) (*ShadowFile, error) {
	b, err := hostfs.ReadFile(path)
	if err != nil {
		return nil, err
	}
	lines, err := readLines(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}

	var pf parsedFile[ShadowEntry]
	for _, line := range lines {
		trim := strings.TrimSpace(line)
		if trim == "" || strings.HasPrefix(trim, "#") {
			pf.lines = append(pf.lines, rawLine[ShadowEntry]{raw: line})
			continue
		}

		parts := parseColonLine(line)
		if len(parts) < 2 {
			pf.lines = append(pf.lines, rawLine[ShadowEntry]{raw: line})
			continue
		}

		for len(parts) < 9 {
			parts = append(parts, "")
		}

		e := ShadowEntry{
			Name:       parts[0],
			Hash:       parts[1],
			LastChange: parts[2],
			Min:        parts[3],
			Max:        parts[4],
			Warn:       parts[5],
			Inactive:   parts[6],
			Expire:     parts[7],
			Reserved:   parts[8],
		}
		pf.lines = append(pf.lines, rawLine[ShadowEntry]{entry: &e})
	}

	return &ShadowFile{pf: pf}, nil
}

func (f *ShadowFile) Find(name string) *ShadowEntry {
	for _, e := range f.pf.entries() {
		if e.Name == name {
			return e
		}
	}
	return nil
}

func (f *ShadowFile) Add(e ShadowEntry) error {
	if f.Find(e.Name) != nil {
		return fmt.Errorf("shadow entry already exists: %s", e.Name)
	}
	f.pf.lines = append(f.pf.lines, rawLine[ShadowEntry]{entry: &e})
	return nil
}

func (f *ShadowFile) Delete(name string) bool {
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
	var nl []rawLine[ShadowEntry]
	for _, ln := range f.pf.lines {
		if ln.entry == nil && ln.raw == "" {
			continue
		}
		nl = append(nl, ln)
	}
	f.pf.lines = nl
	return true
}

func (f *ShadowFile) Bytes() []byte {
	var buf strings.Builder
	for _, ln := range f.pf.lines {
		if ln.entry != nil {
			e := ln.entry
			buf.WriteString(fmt.Sprintf("%s:%s:%s:%s:%s:%s:%s:%s:%s\n",
				e.Name, e.Hash, e.LastChange, e.Min, e.Max, e.Warn, e.Inactive, e.Expire, e.Reserved))
			continue
		}
		buf.WriteString(ln.raw)
		buf.WriteString("\n")
	}
	return []byte(buf.String())
}
