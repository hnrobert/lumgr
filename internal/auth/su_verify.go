package auth

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"time"

	"github.com/creack/pty"
)

var ErrAuthBackend = errors.New("auth backend error")

func verifyWithSu(username, password string) (bool, error) {
	// Use su(1) behind a PTY so BusyBox su can prompt for a password.
	// This works for Ubuntu yescrypt ($y$) and whatever the host supports.
	if strings.TrimSpace(username) == "" {
		return false, ErrInvalidCredentials
	}

	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "su", "-s", "/bin/sh", "-c", "true", username)
	f, err := pty.Start(cmd)
	if err != nil {
		return false, fmt.Errorf("%w: start su: %v", ErrAuthBackend, err)
	}
	defer func() { _ = f.Close() }()

	prompted := false
	var out bytes.Buffer
	readerDone := make(chan struct{})

	go func() {
		defer close(readerDone)
		br := bufio.NewReader(f)
		buf := make([]byte, 4096)
		for {
			_ = f.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			n, rerr := br.Read(buf)
			if n > 0 {
				out.Write(buf[:n])
				lower := strings.ToLower(out.String())
				if !prompted && strings.Contains(lower, "password") {
					prompted = true
					_, _ = io.WriteString(f, password+"\n")
				}
			}
			if rerr != nil {
				return
			}
		}
	}()

	err = cmd.Wait()
	<-readerDone

	if err == nil {
		return true, nil
	}
	if ctx.Err() != nil {
		return false, fmt.Errorf("%w: su timed out", ErrAuthBackend)
	}
	return false, nil
}
