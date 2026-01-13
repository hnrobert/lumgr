package usercmd

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

type Runner struct {
	Timeout time.Duration
}

func New() *Runner {
	return &Runner{Timeout: 10 * time.Second}
}

func (r *Runner) run(name string, args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), r.Timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		s := strings.TrimSpace(stderr.String())
		if s == "" {
			return err
		}
		return fmt.Errorf("%s %v: %s", name, args, s)
	}
	return nil
}

func (r *Runner) runWithStdin(stdin []byte, name string, args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), r.Timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin = bytes.NewReader(stdin)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		s := strings.TrimSpace(stderr.String())
		if s == "" {
			return err
		}
		return fmt.Errorf("%s %v: %s", name, args, s)
	}
	return nil
}

func (r *Runner) AddUser(username, home, shell string) error {
	args := []string{"-D"}
	if home != "" {
		args = append(args, "-h", home)
	}
	if shell != "" {
		args = append(args, "-s", shell)
	}
	args = append(args, username)
	return r.run("adduser", args...)
}

func (r *Runner) SetPassword(username, password string) error {
	// chpasswd reads "user:pass" lines from stdin.
	line := fmt.Sprintf("%s:%s\n", username, password)
	return r.runWithStdin([]byte(line), "chpasswd")
}

func (r *Runner) DelUser(username string, removeHome bool) error {
	args := []string{}
	if removeHome {
		args = append(args, "-r")
	}
	args = append(args, username)
	return r.run("deluser", args...)
}

func (r *Runner) AddUserToGroup(username, group string) error {
	// BusyBox addgroup: addgroup <user> <group>
	return r.run("addgroup", username, group)
}
