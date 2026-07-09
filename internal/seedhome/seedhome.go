// Package seedhome copies a TEMPLATE directory's contents into an anon account's
// home, so an operator can have anonctl populate a fresh account with chosen files
// (dotfiles, a tool config) instead of the near-empty skel home. It is the engine
// behind the `seed-home` verb and behind `add`'s fresh-creation seeding from the
// directory-exists default `/etc/anonctl/default-home/`.
//
// It stays GENERIC: it copies arbitrary files and knows nothing about pi, a model
// provider, or any tool. The pi-specific model seeding lives in anon-pi (see the
// idea note work/notes/ideas/seed-home-and-add-time-defaults.md), which can point
// its own logic at an anonctl account's home.
//
// Two safety rules are load-bearing, not incidental:
//   - COLLISION is an error by default (Force overrides): a seed never silently
//     clobbers a file the account already has.
//   - SETUID/SETGID bits are STRIPPED on every copied file. A template must never
//     introduce a setuid binary: a setuid file the account can run opens a socket
//     owned by a DIFFERENT uid, the uid-transition escape that is the README threat
//     model's sharpest residual. Stripping the bits closes that at seed time.
//
// The recursive copy is ordinary filesystem I/O and is unit-tested against a real
// temp dir (no root, no real home). The chown-to-account step is behind a Runner
// seam (mirroring provision's discipline) so the copy logic is tested without root
// and the real chown runs only on a live host.
package seedhome

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Runner abstracts command execution (the chown) so the copy is unit-testable
// without root. It mirrors provision.Runner intentionally so production wires the
// SAME ExecRunner.
type Runner interface {
	Run(ctx context.Context, name string, args ...string) (stdout, stderr string, err error)
}

// setuidBits are the mode bits stripped from every seeded file: setuid, setgid,
// and sticky. Stripping setuid/setgid closes the uid-transition escape a template
// could otherwise introduce; the sticky bit is stripped with them as it is
// meaningless on a regular file and never something a seeded file should carry.
const setuidBits = fs.ModeSetuid | fs.ModeSetgid | fs.ModeSticky

// ErrCollision reports that a target path already exists and Force was not set. It
// wraps the offending relative paths so the caller can name every collision at
// once (a seed that would clobber files fails LOUD, listing them, before copying
// anything).
type ErrCollision struct {
	// Paths are the template-relative paths whose targets already exist.
	Paths []string
}

func (e *ErrCollision) Error() string {
	return fmt.Sprintf("seed-home: %d file(s) already exist in the home (pass --force to overwrite): %s",
		len(e.Paths), strings.Join(e.Paths, ", "))
}

// Result reports what a seed did: how many files it wrote and the template-
// relative paths it overwrote (non-empty only under Force). Copied counts regular
// files written (directories are created as needed but not counted).
type Result struct {
	Copied    int      `json:"copied"`
	Overwrote []string `json:"overwrote,omitempty"`
}

// Seed copies every file under templateDir into home, chowning each written path
// to account. It is ATOMIC in its collision check: with Force unset it scans for
// ALL collisions first and returns an *ErrCollision (writing nothing) if any
// exist, so a seed never lands a partial set and then aborts. With Force set it
// overwrites, recording the overwritten paths in the Result.
//
// Every regular file is written with its source mode MINUS the setuid/setgid/
// sticky bits (the uid-transition-escape closure). Directories are created 0755.
// Symlinks in the template are refused (a symlink could point a seeded file at an
// arbitrary target owned by another uid, or escape the home): a template is data,
// not a link farm.
func Seed(ctx context.Context, r Runner, templateDir, home, account string, force bool) (Result, error) {
	var res Result

	info, err := os.Stat(templateDir)
	if err != nil {
		return res, fmt.Errorf("seed-home: read template %q: %w", templateDir, err)
	}
	if !info.IsDir() {
		return res, fmt.Errorf("seed-home: template %q is not a directory", templateDir)
	}

	// PASS 1: enumerate the template's regular files + dirs (relative paths), refusing
	// symlinks, and collect any target collisions. Nothing is written in this pass, so
	// a collision (without Force) aborts before touching the home.
	var files, dirs []string
	var collisions []string
	walkErr := filepath.WalkDir(templateDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, rerr := filepath.Rel(templateDir, path)
		if rerr != nil {
			return rerr
		}
		if rel == "." {
			return nil
		}
		if d.Type()&fs.ModeSymlink != 0 {
			return fmt.Errorf("seed-home: template contains a symlink %q; templates must be plain files/dirs", rel)
		}
		if d.IsDir() {
			dirs = append(dirs, rel)
			return nil
		}
		if !d.Type().IsRegular() {
			return fmt.Errorf("seed-home: template entry %q is not a regular file", rel)
		}
		files = append(files, rel)
		target := filepath.Join(home, rel)
		if _, statErr := os.Lstat(target); statErr == nil {
			collisions = append(collisions, rel)
		} else if !errors.Is(statErr, os.ErrNotExist) {
			return fmt.Errorf("seed-home: stat target %q: %w", target, statErr)
		}
		return nil
	})
	if walkErr != nil {
		return res, walkErr
	}
	if len(collisions) > 0 && !force {
		sort.Strings(collisions)
		return res, &ErrCollision{Paths: collisions}
	}

	// PASS 2: create dirs then copy files. Directories first (shallowest first via the
	// walk's lexical order) so a file's parent always exists.
	sort.Strings(dirs)
	for _, rel := range dirs {
		dst := filepath.Join(home, rel)
		if err := os.MkdirAll(dst, 0o755); err != nil {
			return res, fmt.Errorf("seed-home: create dir %q: %w", rel, err)
		}
		// Chown the created directory to the account too, not just the files inside it.
		// A root-run seed's os.MkdirAll leaves the dir owned by root, so the account
		// could READ the seeded files but not CREATE new entries under the dir (locks,
		// caches, session subdirs): the exact EACCES a tool like `pi` hits when it tries
		// to mkdir under a seeded `.pi/agent/`. Directories are chowned before the files
		// so every seeded path ends up account-owned.
		if _, _, err := r.Run(ctx, "chown", account+":"+account, dst); err != nil {
			return res, fmt.Errorf("seed-home: chown dir %q to %s: %w", dst, account, err)
		}
	}
	sort.Strings(files)
	for _, rel := range files {
		src := filepath.Join(templateDir, rel)
		dst := filepath.Join(home, rel)
		existed := false
		if _, statErr := os.Lstat(dst); statErr == nil {
			existed = true
		}
		if err := copyFile(src, dst); err != nil {
			return res, err
		}
		if _, _, err := r.Run(ctx, "chown", account+":"+account, dst); err != nil {
			return res, fmt.Errorf("seed-home: chown %q to %s: %w", dst, account, err)
		}
		res.Copied++
		if existed {
			res.Overwrote = append(res.Overwrote, rel)
		}
	}
	return res, nil
}

// copyFile copies src to dst, applying the source mode with the setuid/setgid/
// sticky bits stripped (the uid-transition-escape closure). It overwrites dst if
// present (the caller has already gated on collisions/force). The mode is
// re-asserted after write because os.OpenFile respects umask.
func copyFile(src, dst string) error {
	info, err := os.Stat(src)
	if err != nil {
		return fmt.Errorf("seed-home: stat %q: %w", src, err)
	}
	mode := info.Mode().Perm() &^ os.FileMode(setuidBits)
	data, err := os.ReadFile(src)
	if err != nil {
		return fmt.Errorf("seed-home: read %q: %w", src, err)
	}
	if err := os.WriteFile(dst, data, mode); err != nil {
		return fmt.Errorf("seed-home: write %q: %w", dst, err)
	}
	if err := os.Chmod(dst, mode); err != nil {
		return fmt.Errorf("seed-home: chmod %q: %w", dst, err)
	}
	return nil
}
