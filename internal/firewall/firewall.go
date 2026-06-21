package firewall

import (
	"bytes"
	"fmt"
	"os/exec"
	"strconv"
)

// Manager opens/closes network access to a port for a given source CIDR.
// Abstracted so we can swap ufw for nftables later, or use Noop in tests.
type Manager interface {
	Allow(cidr string, port int, comment string) error
	Deny(cidr string, port int) error
}

// UFW shells out to Ubuntu's `ufw`. Requires the daemon to run as root.
type UFW struct{ Bin string }

func NewUFW() *UFW { return &UFW{Bin: "ufw"} }

func (u *UFW) Allow(cidr string, port int, comment string) error {
	return run(u.bin(),
		"allow", "from", cidr,
		"to", "any", "port", strconv.Itoa(port),
		"proto", "tcp",
		"comment", comment,
	)
}

func (u *UFW) Deny(cidr string, port int) error {
	// ufw matches the rule for deletion by its spec (comment is ignored).
	return run(u.bin(),
		"delete", "allow", "from", cidr,
		"to", "any", "port", strconv.Itoa(port),
		"proto", "tcp",
	)
}

func (u *UFW) bin() string {
	if u.Bin == "" {
		return "ufw"
	}
	return u.Bin
}

func run(bin string, args ...string) error {
	// Resolve the full canonical path (following symlinks) so it matches
	// the sudoers rule exactly. On Ubuntu 22.04+ /usr/sbin is a symlink to
	// /usr/bin, so "ufw" resolves to /usr/bin/ufw — the sudoers rule must
	// use the same resolved path.
	fullPath, err := exec.LookPath(bin)
	if err != nil {
		return fmt.Errorf("cannot find %s in PATH: %w", bin, err)
	}
	// -n = non-interactive: fail immediately rather than prompt for confirmation.
	cmd := exec.Command(fullPath, append([]string{"-n"}, args...)...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("ufw %v: %w\n%s", args, err, out.String())
	}
	return nil
}
