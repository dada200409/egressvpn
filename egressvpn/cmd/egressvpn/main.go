package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/dada200409/egressvpn/internal/config"
	"github.com/dada200409/egressvpn/internal/render"
	"github.com/dada200409/egressvpn/internal/wgkey"
)

// version is injected at build time with -ldflags "-X main.version=...".
// A server that has been running for months is impossible to debug without
// knowing which build is on it.
var version = "dev"

const usage = `egressvpn - render an IKEv2 + chained-egress server config from a YAML table

  egressvpn genkey            WireGuard keypair (for upstream B's [Peer] block)
  egressvpn genpsk            WireGuard preshared key
  egressvpn validate -c X     parse and check X
  egressvpn render -c X -o D  write egressvpn.conf / egress.nft / wg confs / apply.sh
  egressvpn version           build identifier

apply.sh is generated, never executed, by design: it alters routing on a live
host, so it has to be reviewed and run by hand.
`

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		fmt.Print(usage)
		return nil
	}
	switch cmd, rest := args[0], args[1:]; cmd {
	case "genkey":
		priv, pub, err := wgkey.GenKeyPair()
		if err != nil {
			return err
		}
		fmt.Printf("private (keep secret, mode 0600):\n  %s\npublic (goes in the config):\n  %s\n", priv, pub)
		return nil
	case "genpsk":
		psk, err := wgkey.GenPSK()
		if err != nil {
			return err
		}
		fmt.Println(psk)
		return nil
	case "version":
		fmt.Println(version)
		return nil
	case "-h", "--help", "help":
		fmt.Print(usage)
		return nil
	case "validate", "render":
		fs := flag.NewFlagSet(cmd, flag.ExitOnError)
		confPath := fs.String("c", "egress.yaml", "config YAML path")
		outDir := fs.String("o", "out", "output directory (render only)")
		if err := fs.Parse(rest); err != nil {
			return err
		}
		c, err := config.Load(*confPath)
		if err != nil {
			return err
		}
		if cmd == "validate" {
			fmt.Printf("ok: %d face(s), %d upstream(s), %d user(s)\n",
				len(c.Faces), len(c.Upstreams), len(c.Users))
			return nil
		}
		return write(*outDir, c)
	}
	return errors.New("unknown command " + args[0] + "\n\n" + usage)
}

func write(dir string, c *config.Config) error {
	f, err := render.Render(c)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	// carries the EAP secrets, so it must not be world readable. Installed as
	// /etc/swanctl/conf.d/egressvpn.conf; swanctl has no --file option.
	files := map[string]struct {
		body string
		mode os.FileMode
	}{
		"egressvpn.conf":      {f.Swanctl, 0o600},
		"charon-snippet.conf": {f.CharonSnippet, 0o644},
		"egress.nft":          {f.Nft, 0o644},
		"sysctl.conf":         {f.Sysctl, 0o644},
		"routes.sh":           {f.Routes, 0o755},
		// the unit names have to match on disk, so these files are already named
		// for /etc/systemd/system/.
		"egressvpn-routes.service": {f.RoutesUnit, 0o644},
		"egressvpn-routes.timer":   {f.RoutesTimer, 0o644},
		"apply.sh":                 {f.Apply, 0o755},
		"verify.sh":                {f.Verify, 0o755},
	}
	for name, v := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(v.body), v.mode); err != nil {
			return err
		}
		fmt.Println("wrote", filepath.Join(dir, name))
	}
	for _, u := range c.Upstreams {
		if u.OverTCP() {
			// A tcp-ssh hop-2 needs no wg conf: the link is created by ssh at run
			// time, so what ships is a runner, a unit and the client config it reads.
			arts := []struct {
				file string
				body string
				mode os.FileMode
			}{
				{"hop2-" + u.Name + "-runner.sh", f.Hop2Runner[u.Name], 0o755},
				{"hop2-" + u.Name + ".service", f.Hop2Unit[u.Name], 0o644},
				{"hop2-" + u.Name + "_ssh_config", f.Hop2SshCfg[u.Name], 0o600},
			}
			for _, a := range arts {
				p := filepath.Join(dir, a.file)
				if err := os.WriteFile(p, []byte(a.body), a.mode); err != nil {
					return err
				}
				fmt.Println("wrote", p)
			}
		} else {
			aName := filepath.Join(dir, u.Interface+".conf")
			if err := os.WriteFile(aName, []byte(f.WireGuard[u.Name]), 0o600); err != nil {
				return err
			}
			fmt.Println("wrote", aName)
		}
		bName := filepath.Join(dir, "B-"+u.Name+"-peer.txt")
		if err := os.WriteFile(bName, []byte(f.PeerSnippets[u.Name]), 0o644); err != nil {
			return err
		}
		fmt.Println("wrote", bName, "(paste this block into server B)")
	}

	// profiles carry the CA and, unless embed-password is off, the EAP password
	profDir := filepath.Join(dir, "profiles")
	if err := os.MkdirAll(profDir, 0o700); err != nil {
		return err
	}
	for _, u := range c.Users {
		p := filepath.Join(profDir, f.ProfileNames[u.Name])
		if err := os.WriteFile(p, []byte(f.Profiles[u.Name]), 0o600); err != nil {
			return err
		}
		fmt.Println("wrote", p)
	}
	return nil
}
