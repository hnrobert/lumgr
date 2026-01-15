package usermgr

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"
)

type rawLine[T any] struct {
	raw   string
	entry *T
}

type parsedFile[T any] struct {
	lines []rawLine[T]
}

func (pf *parsedFile[T]) entries() []*T {
	out := make([]*T, 0, len(pf.lines))
	for i := range pf.lines {
		if pf.lines[i].entry != nil {
			out = append(out, pf.lines[i].entry)
		}
	}
	return out
}

func parseColonLine(line string) []string {
	// Keep trailing empty fields.
	return strings.Split(line, ":")
}

func readLines(r io.Reader) ([]string, error) {
	s := bufio.NewScanner(r)
	buf := make([]byte, 0, 64*1024)
	s.Buffer(buf, 1024*1024)
	var lines []string
	for s.Scan() {
		lines = append(lines, s.Text())
	}
	if err := s.Err(); err != nil {
		return nil, err
	}
	return lines, nil
}

func atoi(field, ctx string) (int, error) {
	n, err := strconv.Atoi(field)
	if err != nil {
		return 0, fmt.Errorf("invalid int %q in %s: %w", field, ctx, err)
	}
	return n, nil
}
