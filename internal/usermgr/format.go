package usermgr

import (
	"strings"
)

// Small helper to avoid strconv import in hot formatting.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [32]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + (n % 10))
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

func FormatPasswd(lines []FileLine) string {
	var b strings.Builder
	for _, l := range lines {
		switch l.Kind {
		case LineRaw:
			b.WriteString(l.Raw)
		case LinePasswd:
			e := l.Passwd
			b.WriteString(e.Name)
			b.WriteByte(':')
			b.WriteString(e.Passwd)
			b.WriteByte(':')
			b.WriteString(itoa(e.UID))
			b.WriteByte(':')
			b.WriteString(itoa(e.GID))
			b.WriteByte(':')
			b.WriteString(e.Gecos)
			b.WriteByte(':')
			b.WriteString(e.Home)
			b.WriteByte(':')
			b.WriteString(e.Shell)
			b.WriteByte('\n')
		default:
			b.WriteString(l.Raw)
		}
	}
	return b.String()
}

func FormatGroup(lines []FileLine) string {
	var b strings.Builder
	for _, l := range lines {
		switch l.Kind {
		case LineRaw:
			b.WriteString(l.Raw)
		case LineGroup:
			e := l.Group
			b.WriteString(e.Name)
			b.WriteByte(':')
			b.WriteString(e.Passwd)
			b.WriteByte(':')
			b.WriteString(itoa(e.GID))
			b.WriteByte(':')
			b.WriteString(strings.Join(e.Members, ","))
			b.WriteByte('\n')
		default:
			b.WriteString(l.Raw)
		}
	}
	return b.String()
}

func FormatShadow(lines []FileLine) string {
	var b strings.Builder
	for _, l := range lines {
		switch l.Kind {
		case LineRaw:
			b.WriteString(l.Raw)
		case LineShadow:
			e := l.Shadow
			b.WriteString(e.Name)
			b.WriteByte(':')
			b.WriteString(e.Hash)
			b.WriteByte(':')
			b.WriteString(e.LastChange)
			b.WriteByte(':')
			b.WriteString(e.Min)
			b.WriteByte(':')
			b.WriteString(e.Max)
			b.WriteByte(':')
			b.WriteString(e.Warn)
			b.WriteByte(':')
			b.WriteString(e.Inactive)
			b.WriteByte(':')
			b.WriteString(e.Expire)
			b.WriteByte(':')
			b.WriteString(e.Reserved)
			b.WriteByte('\n')
		default:
			b.WriteString(l.Raw)
		}
	}
	return b.String()
}
