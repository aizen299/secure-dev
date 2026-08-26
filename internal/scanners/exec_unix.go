//go:build unix

package scanners

import (
	"os/exec"
	"syscall"
)

// configureProcessGroup puts the child in its own process group so the whole
// tree can be signalled together.
func configureProcessGroup(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setpgid = true
}

// killProcessGroup terminates the child and every process it spawned. A scanner
// that leaks a child would otherwise keep the ephemeral workspace alive past
// the job's timeout.
func killProcessGroup(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return nil
	}
	// The negative PID targets the group created by configureProcessGroup.
	if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); err != nil {
		return cmd.Process.Kill()
	}
	return nil
}
