package files

import (
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// Level is the impersonation level of an access token, in the order of the
// SECURITY_IMPERSONATION_LEVEL enumeration: anonymous, identification,
// impersonation, delegation.
type Level int

// The impersonation levels. A token below LevelImpersonation can identify
// its user but cannot be impersonated (profile IA-6).
const (
	LevelAnonymous Level = iota
	LevelIdentification
	LevelImpersonation
	LevelDelegation
)

// Token is the access token of a completed Negotiate exchange: the user's
// security context on the broker's host.
type Token interface {
	// User is the user SID of the token, in the S-1-... text form.
	User() string
	// Groups are the group SIDs of the token, in token order.
	Groups() []string
	// Level is the token's impersonation level.
	Level() Level
	// Ref names the token's logon session and token instance, for the
	// source reference of a claim.
	Ref() string
	// Close releases the token.
	Close() error
}

// SecurityPackage is the server side of the Negotiate exchange (profile
// 3.1): on Windows the security package interface, [NewSSPI].
type SecurityPackage interface {
	// NewExchange starts the exchange of one connection.
	NewExchange() (Exchange, error)
}

// Exchange is one Negotiate exchange in progress.
type Exchange interface {
	// Accept passes one token of the client to the package. It returns the
	// token to send back and, when the exchange is complete, the access
	// token of the context. A nil token and a nil error mean that another
	// leg is needed. An error is a failed exchange.
	Accept(input []byte) (output []byte, tok Token, err error)
	// Close deletes the context, partial or complete.
	Close() error
}

// Impersonator impersonates an access token on the calling operating-system
// thread, which the broker has locked (profile 3.5); on Windows
// [ThreadImpersonator].
type Impersonator interface {
	// Impersonate makes tok the calling thread's token.
	Impersonate(tok Token) error
	// Effective returns the user SID of the calling thread's effective
	// token.
	Effective() (string, error)
	// Revert ends the impersonation of the calling thread.
	Revert() error
}

// Access is an access right the broker requests at an open.
type Access string

// AccessRead is the read access of route R1 (profile ER-3).
const AccessRead Access = "read"

// FileSystem opens files as the calling thread's identity: open-existing,
// opening a reparse point as itself, never with backup semantics (profile
// ER-4, ER-5); on Windows [NTFS].
type FileSystem interface {
	// Open opens path for access. An open the native access check refuses
	// returns an error that wraps [ErrAccessDenied].
	Open(path string, access Access) (Handle, error)
}

// Handle is an open file.
type Handle interface {
	io.Reader
	// Object reports what the handle opened.
	Object() (Object, error)
	// Close closes the handle.
	Close() error
}

// ErrAccessDenied is the native denial of an open.
var ErrAccessDenied = errors.New("files: the native access check denied the open")

// Attributes are file attribute bits, with the values of the Windows file
// attribute constants.
type Attributes uint32

// The attributes the broker checks after an open (profile PB-4). The values
// are those of FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
// FILE_ATTRIBUTE_OFFLINE and FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS on the
// Windows file attribute constants page.
const (
	AttrDirectory          Attributes = 0x00000010
	AttrReparsePoint       Attributes = 0x00000400
	AttrOffline            Attributes = 0x00001000
	AttrRecallOnDataAccess Attributes = 0x00400000
)

// Object is what an open handle reports: the attributes of its file, the
// volume serial number and 128-bit file identifier that identify the file on
// one computer, and the final path of the handle.
type Object struct {
	Attributes   Attributes
	VolumeSerial uint64
	ObjectID     [16]byte
	FinalPath    string
}

// Entry is an entry of the file registry (profile PB-1): the resource it
// serves, the configured local path, and the final path, volume serial
// number and file identifier recorded at registration.
type Entry struct {
	Resource     string
	Path         string
	FinalPath    string
	VolumeSerial uint64
	ObjectID     [16]byte
}

// Registry is the file registry, trusted configuration that only an
// administrator changes.
type Registry interface {
	// Lookup returns the entry of resource.
	Lookup(resource string) (Entry, bool)
}

// StaticRegistry is a Registry held in memory, by resource.
type StaticRegistry map[string]Entry

// Lookup returns the entry of resource.
func (r StaticRegistry) Lookup(resource string) (Entry, bool) {
	e, ok := r[resource]
	return e, ok
}

// Register opens path as the calling identity and records the entry of
// resource from that one handle, so that the final path, the volume serial
// number and the file identifier describe one object (profile PB-2). It
// refuses a path that is not a fully qualified local path with a drive
// letter, one with a "." or ".." component, a device-namespace or network
// prefix, a stream name, or a forward slash, and an object that the broker
// would refuse to serve.
func Register(fs FileSystem, resource, path string) (Entry, error) {
	if err := localPath(path); err != nil {
		return Entry{}, err
	}
	h, err := fs.Open(path, AccessRead)
	if err != nil {
		return Entry{}, fmt.Errorf("files: register %s: %w", path, err)
	}
	defer func() { _ = h.Close() }()
	obj, err := h.Object()
	if err != nil {
		return Entry{}, fmt.Errorf("files: register %s: %w", path, err)
	}
	if err := served(obj); err != nil {
		return Entry{}, fmt.Errorf("files: register %s: %w", path, err)
	}
	return Entry{Resource: resource, Path: path, FinalPath: obj.FinalPath, VolumeSerial: obj.VolumeSerial, ObjectID: obj.ObjectID}, nil
}

// localPath accepts only X:\ followed by plain components.
func localPath(path string) error {
	if len(path) < 4 || !isLetter(path[0]) || path[1] != ':' || path[2] != '\\' {
		return fmt.Errorf("files: %q is not a fully qualified local path", path)
	}
	for _, c := range strings.Split(path[3:], `\`) {
		switch {
		case c == "", c == ".", c == "..":
			return fmt.Errorf("files: %q has an empty, . or .. component", path)
		case strings.ContainsAny(c, `:/*?"<>|`):
			return fmt.Errorf("files: %q has a stream name or a reserved character", path)
		}
	}
	return nil
}

func isLetter(b byte) bool { return (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') }

// PrincipalID returns the identifier of the account sid names:
// files:{domain-sid}:{sid}, the domain SID being the SID without its last
// subauthority (identity mapping section 3.3, profile IA-8). It refuses
// anything that is not a SID in S-1-... text form with at least one
// subauthority.
func PrincipalID(sid string) (string, error) {
	parts := strings.Split(sid, "-")
	if len(parts) < 4 || parts[0] != "S" || parts[1] != "1" {
		return "", fmt.Errorf("files: %q is not a SID with a subauthority", sid)
	}
	for _, p := range parts[2:] {
		if _, err := strconv.ParseUint(p, 10, 64); err != nil || p == "" || (len(p) > 1 && p[0] == '0') {
			return "", fmt.Errorf("files: %q is not a SID with a subauthority", sid)
		}
	}
	return "files:" + strings.Join(parts[:len(parts)-1], "-") + ":" + sid, nil
}
