package usermgr

type PasswdEntry struct {
	Name   string
	Passwd string
	UID    int
	GID    int
	Gecos  string
	Home   string
	Shell  string
}

type ShadowEntry struct {
	Name       string
	Hash       string
	LastChange string
	Min        string
	Max        string
	Warn       string
	Inactive   string
	Expire     string
	Reserved   string
}

type GroupEntry struct {
	Name    string
	Passwd  string
	GID     int
	Members []string
}

type FileLineKind int

const (
	LineRaw FileLineKind = iota
	LinePasswd
	LineShadow
	LineGroup
)

type FileLine struct {
	Kind   FileLineKind
	Raw    string
	Passwd *PasswdEntry
	Shadow *ShadowEntry
	Group  *GroupEntry
}
