package firewall

import (
	"bytes"
	"fmt"
	"net"
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
		"allow", "from", ufwHost(cidr),
		"to", "any", "port", strconv.Itoa(port),
		"proto", "tcp",
	)
}

func (u *UFW) Deny(cidr string, port int) error {
	// ufw matches the rule for deletion by its spec (comment is ignored).
	return run(u.bin(),
		"delete", "allow", "from", ufwHost(cidr),
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

// ufwHost converts a CIDR into the form UFW accepts in "from" rules.
// UFW rejects /128 for IPv6 single hosts and is picky about /32 too,
// so we strip the prefix for exact-host CIDRs.
func ufwHost(cidr string) string {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		// Not a CIDR — pass through as-is (bare IP or hostname).
		return cidr
	}
	ones, bits := ipnet.Mask.Size()
	if ones == bits {
		// /32 or /128 — single host; UFW wants just the IP.
		return ip.String()
	}
	return cidr
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
	sudoPath, err := exec.LookPath("sudo")
	if err != nil {
		return fmt.Errorf("cannot find sudo in PATH: %w", err)
	}
	// Run as: sudo <ufw-path> <args>
	// The flashaccess service user has a NOPASSWD sudoers rule for the ufw binary.
	cmd := exec.Command(sudoPath, append([]string{fullPath}, args...)...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("ufw %v: %w\n%s", args, err, out.String())
	}
	return nil
}

// Noop is a firewall.Manager that does nothing.
// Used when FLASHACCESS_NOFW=1 (testing / environments without ufw).
type Noop struct{}

func (Noop) Allow(cidr string, port int, comment string) error { return nil }
func (Noop) Deny(cidr string, port int) error                  { return nil }
