package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/sys/unix"
)

const recordingSuffix = ".record"

// Pin each directory before walking the next component. No untrusted user
// may replace a component, and neither the spool nor its entries may be links.
func openRecordingSpool(create bool) (*os.File, error) {
	path := os.Getenv("FIDES_SPOOL_DIR")
	if path == "" {
		dir, err := os.UserConfigDir()
		if err != nil {
			return nil, err
		}
		path = filepath.Join(dir, "fides", "recordings")
	}
	path = filepath.Clean(path)
	if !filepath.IsAbs(path) || path == "/" {
		return nil, errors.New("FIDES_SPOOL_DIR must be an absolute path to a private directory")
	}

	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer func() {
		if fd >= 0 {
			_ = unix.Close(fd)
		}
	}()
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	uid := uint32(os.Geteuid()) // #nosec G115 -- OS uid fits in the platform's uint32 stat field
	for i, name := range parts {
		openFlags := unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC
		next, err := unix.Openat(fd, name, openFlags, 0)
		if errors.Is(err, unix.ENOENT) {
			if !create {
				return nil, nil
			}
			if err = unix.Mkdirat(fd, name, 0700); err != nil && !errors.Is(err, unix.EEXIST) {
				return nil, fmt.Errorf("create recording spool: %w", err)
			}
			next, err = unix.Openat(fd, name, openFlags, 0)
		}
		if err != nil {
			return nil, fmt.Errorf("open recording spool component %q: %w", name, err)
		}
		// Another process may have created a visible parent entry before syncing it.
		if create {
			if err := unix.Fsync(fd); err != nil {
				_ = unix.Close(next)
				return nil, fmt.Errorf("sync recording spool parent: %w", err)
			}
		}
		_ = unix.Close(fd)
		fd = next

		var stat unix.Stat_t
		if err := unix.Fstat(fd, &stat); err != nil {
			return nil, err
		}
		if i == len(parts)-1 {
			if stat.Uid != uid || stat.Mode&07777 != 0700 {
				return nil, errors.New("recording spool must be owned by the current user with mode 0700")
			}
		} else if (stat.Uid != 0 && stat.Uid != uid) ||
			(stat.Mode&0022 != 0 && stat.Mode&unix.S_ISVTX == 0) {
			return nil, fmt.Errorf("unsafe recording spool ancestor %q", name)
		}
	}
	for {
		err = unix.Flock(fd, unix.LOCK_EX)
		if !errors.Is(err, unix.EINTR) {
			break
		}
	}
	if err != nil {
		return nil, fmt.Errorf("lock recording spool: %w", err)
	}
	spool := os.NewFile(uintptr(fd), path)
	fd = -1
	// A previous process may have renamed a confirmed trail before syncing.
	if err := spool.Sync(); err != nil {
		spool.Close()
		return nil, fmt.Errorf("sync recording spool: %w", err)
	}
	return spool, nil
}

func queueRecording(spool *os.File, entry recording, body []byte, reason string) (string, error) {
	if err := saveRecording(spool, entry, body); err != nil {
		return "", fmt.Errorf("persist recording: %w", err)
	}
	ref := offlinePrefix + entry.Key.String()
	fmt.Fprintf(os.Stderr, "Warning: %s. Evidence queued locally (%s).\n", reason, ref)
	result, err := json.Marshal(map[string]any{"id": ref, "queued": true})
	return string(result), err
}

func saveRecording(spool *os.File, entry recording, body []byte) error {
	dirFD := int(spool.Fd())
	temp := "." + uuid.NewString() + ".tmp"
	fd, err := unix.Openat(dirFD, temp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Unlinkat(dirFD, temp, 0) }()
	file := os.NewFile(uintptr(fd), temp)
	if err := file.Chmod(0600); err != nil {
		file.Close()
		return err
	}
	if err := json.NewEncoder(file).Encode(entry); err != nil {
		file.Close()
		return err
	}
	if _, err := file.Write(body); err != nil {
		file.Close()
		return err
	}
	err = file.Sync()
	if err := errors.Join(err, file.Close()); err != nil {
		return err
	}
	if err := unix.Renameat(dirFD, temp, dirFD, entry.Key.String()+recordingSuffix); err != nil {
		return err
	}
	return spool.Sync()
}

func readRecording(spool *os.File, key uuid.UUID, includeBody bool) (recording, []byte, time.Time, error) {
	var entry recording
	var created time.Time
	name := key.String() + recordingSuffix
	dirFD := int(spool.Fd())
	fd, err := unix.Openat(dirFD, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return entry, nil, created, err
	}
	file := os.NewFile(uintptr(fd), name)
	defer file.Close()

	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return entry, nil, created, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&07777 != 0600 ||
		stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 { // #nosec G115 -- uid is uint32
		return entry, nil, created, errors.New("recording entry must be a private regular file with no additional links")
	}
	info, err := file.Stat()
	if err != nil {
		return entry, nil, created, err
	}
	reader := bufio.NewReader(file)
	header, err := reader.ReadSlice('\n')
	if err != nil {
		return entry, nil, created, err
	}
	if err := json.Unmarshal(header, &entry); err != nil {
		return entry, nil, created, err
	}
	if entry.Key != key || (entry.Path != trailRecord && entry.Path != artifactRecord && entry.Path != attestationRecord) ||
		(entry.ConfirmedTrail != uuid.Nil && entry.Path != trailRecord) {
		return entry, nil, created, errors.New("invalid recording metadata")
	}
	if !includeBody {
		return entry, nil, info.ModTime(), nil
	}
	size := info.Size() - int64(len(header))
	if size <= 0 || size > maxRecordingBody {
		return entry, nil, created, errors.New("invalid recording body length")
	}
	body := make([]byte, size)
	_, err = io.ReadFull(reader, body)
	return entry, body, info.ModTime(), err
}

func listRecordings(spool *os.File) ([]recording, error) {
	if _, err := spool.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	names, err := spool.Readdirnames(-1)
	if err != nil {
		return nil, err
	}
	type queued struct {
		entry   recording
		created time.Time
	}
	pending := []queued{}
	for _, name := range names {
		id, ok := strings.CutSuffix(name, recordingSuffix)
		if !ok {
			continue
		}
		key, err := uuid.Parse(id)
		if err != nil || key == uuid.Nil || key.String() != id {
			return nil, fmt.Errorf("invalid recording filename %q", name)
		}
		entry, _, created, err := readRecording(spool, key, false)
		if err != nil {
			return nil, fmt.Errorf("read recording %s: %w", key, err)
		}
		if entry.ConfirmedTrail == uuid.Nil {
			pending = append(pending, queued{entry, created})
		}
	}
	slices.SortFunc(pending, func(a, b queued) int {
		if byTime := a.created.Compare(b.created); byTime != 0 {
			return byTime
		}
		return strings.Compare(a.entry.Key.String(), b.entry.Key.String())
	})
	entries := make([]recording, len(pending))
	for i, item := range pending {
		entries[i] = item.entry
	}
	return entries, nil
}

func resolveRecordingTrail(spool *os.File, entry recording) (uuid.UUID, error) {
	ref, _, _, err := readRecording(spool, entry.TrailRef, false)
	if err != nil {
		return uuid.Nil, fmt.Errorf("read offline trail %s: %w", entry.TrailRef, err)
	}
	if ref.Path != trailRecord || ref.Binding != entry.Binding {
		return uuid.Nil, fmt.Errorf("offline trail %s does not belong to this endpoint and credential", entry.TrailRef)
	}
	return ref.ConfirmedTrail, nil
}

func handleReplay(config CLIConfig, args []string) {
	cmd := flag.NewFlagSet("replay", flag.ExitOnError)
	cmd.Parse(args)
	if cmd.NArg() != 0 {
		fail(errors.New("usage: fides replay"), "replay")
	}
	count, err := replayRecordings(config)
	fmt.Printf("Replayed %d recording(s).\n", count)
	fail(err, "replay")
}

func replayRecordings(config CLIConfig) (int, error) {
	spool, err := openRecordingSpool(false)
	if err != nil || spool == nil {
		return 0, err
	}
	defer spool.Close()
	all, err := listRecordings(spool)
	if err != nil || len(all) == 0 {
		return 0, err
	}
	base, binding, err := recordingEndpoint(config)
	if err != nil {
		return 0, err
	}
	pending := slices.DeleteFunc(all, func(entry recording) bool { return entry.Binding != binding })
	if len(pending) == 0 {
		return 0, errors.New("queued recordings belong to a different Fides endpoint or credential")
	}
	artifacts := make(map[string]int)
	for _, entry := range pending {
		if entry.Path == artifactRecord {
			artifacts[entry.ArtifactSHA]++
		}
	}
	var result error
	var count, blocked int
	for i := 0; i < len(pending); i++ {
		entry := pending[i]
		if entry.Key == uuid.Nil {
			continue // Already attempted in this invocation.
		}
		trail := uuid.Nil
		if entry.TrailRef != uuid.Nil {
			trail, err = resolveRecordingTrail(spool, entry)
			if err != nil {
				result = errors.Join(result, err)
				pending[i].Key = uuid.Nil
				continue
			}
		}
		if (entry.TrailRef != uuid.Nil && trail == uuid.Nil) ||
			(entry.Path == attestationRecord && artifacts[entry.ArtifactSHA] > 0) {
			blocked++
			continue
		}
		pending[i].Key = uuid.Nil
		_, body, _, err := readRecording(spool, entry.Key, true)
		if err == nil && trail != uuid.Nil {
			body, err = entry.withTrail(body, trail)
		}
		if err != nil {
			return count, errors.Join(result, fmt.Errorf("read recording %s: %w", entry.Key, err))
		}

		response, status, retryable, err := sendRecording(config, base, entry, body)
		if err != nil {
			result = errors.Join(result, fmt.Errorf("recording %s: %w", entry.Key, err))
			if retryable || status == 0 || status == http.StatusUnauthorized || status == http.StatusForbidden ||
				(status >= 300 && status < 400) {
				return count, result
			}
			continue
		}
		if err := confirmRecording(spool, entry, response, status); err != nil {
			return count, errors.Join(result, fmt.Errorf("confirm recording %s: %w", entry.Key, err))
		}
		count++
		if entry.Path == artifactRecord {
			artifacts[entry.ArtifactSHA]--
		}
		if blocked > 0 && (entry.Path == trailRecord || entry.Path == artifactRecord) {
			i, blocked = -1, 0
		}
	}
	if blocked > 0 {
		result = errors.Join(result, fmt.Errorf("%d recording(s) still waiting for dependencies", blocked))
	}
	return count, result
}

func (entry recording) confirmedID(response string, status int) (uuid.UUID, error) {
	var saved struct {
		ID     uuid.UUID `json:"id"`
		SHA256 string    `json:"sha256"`
	}
	if status != http.StatusCreated || json.Unmarshal([]byte(response), &saved) != nil ||
		(entry.Path != artifactRecord && saved.ID == uuid.Nil) ||
		(entry.Path == artifactRecord && saved.SHA256 != entry.ArtifactSHA) {
		return uuid.Nil, errors.New("could not confirm creation with Fides")
	}
	return saved.ID, nil
}

func confirmRecording(spool *os.File, entry recording, response string, status int) error {
	id, err := entry.confirmedID(response, status)
	if err != nil {
		return err
	}
	if entry.Path == trailRecord {
		return saveRecording(spool, recording{Key: entry.Key, Path: entry.Path, Binding: entry.Binding, ConfirmedTrail: id}, nil)
	}
	if err := unix.Unlinkat(int(spool.Fd()), entry.Key.String()+recordingSuffix, 0); err != nil {
		return err
	}
	return spool.Sync()
}
