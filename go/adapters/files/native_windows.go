//go:build windows

package files

import (
	"errors"
	"fmt"
	"io"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ThreadImpersonator returns the impersonation of the calling thread by
// thread assignment: SetThreadToken with a null thread handle assigns the
// impersonation token to the calling thread, and RevertToSelf ends it
// (profile TA-5, TA-7). The broker calls it on a locked thread only.
func ThreadImpersonator() Impersonator { return threadImpersonator{} }

type threadImpersonator struct{}

// Impersonate assigns the token of a completed exchange of this package to
// the calling thread. The SetThreadToken page requires a handle opened with
// TOKEN_IMPERSONATE; which rights the handle of QuerySecurityContextToken
// carries is to probe (OI-1, OI-2).
func (threadImpersonator) Impersonate(tok Token) error {
	wt, ok := tok.(*winToken)
	if !ok {
		return errors.New("files: the token is not a Windows access token")
	}
	if err := windows.SetThreadToken(nil, wt.t); err != nil {
		return fmt.Errorf("files: SetThreadToken: %w", err)
	}
	return nil
}

// Effective returns the user SID of the calling thread's token, opened with
// OpenAsSelf so that the access check of the open is the process's. A
// thread with no token of its own runs with the process token; that
// OpenThreadToken then fails with ERROR_NO_TOKEN is to probe, since the page
// does not state it.
func (threadImpersonator) Effective() (string, error) {
	var t windows.Token
	err := windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY, true, &t)
	if errors.Is(err, windows.ERROR_NO_TOKEN) {
		t = windows.GetCurrentProcessToken()
	} else if err != nil {
		return "", fmt.Errorf("files: OpenThreadToken: %w", err)
	} else {
		defer func() { _ = t.Close() }()
	}
	u, err := t.GetTokenUser()
	if err != nil {
		return "", fmt.Errorf("files: thread token user: %w", err)
	}
	return u.User.Sid.String(), nil
}

// Revert ends the impersonation (RevertToSelf). The page says that when it
// fails the application keeps running in the client's context and should
// shut down the process; the broker marks itself unhealthy (TA-6).
func (threadImpersonator) Revert() error { return windows.RevertToSelf() }

// NTFS returns the local file system of the broker: CreateFileW with the
// read access of profile ER-3, the open-existing disposition, a sharing mode
// that denies native users nothing, null security attributes, which make
// the handle not inheritable, and FILE_FLAG_OPEN_REPARSE_POINT, never
// FILE_FLAG_BACKUP_SEMANTICS (ER-4 to ER-6).
func NTFS() FileSystem { return ntfs{} }

type ntfs struct{}

// readMask is FILE_READ_DATA and FILE_READ_ATTRIBUTES, where ER-3 starts; the
// smallest mask the read and the handle queries need is OI-5.
const readMask = windows.FILE_READ_DATA | windows.FILE_READ_ATTRIBUTES

func (ntfs) Open(path string, access Access) (Handle, error) {
	if access != AccessRead {
		return nil, fmt.Errorf("files: access %q is not served", access)
	}
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(p, readMask,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		// Which error a denied open returns is OI-5.
		return nil, fmt.Errorf("files: %s: %w", path, ErrAccessDenied)
	}
	if err != nil {
		return nil, fmt.Errorf("files: CreateFileW %s: %w", path, err)
	}
	return &ntfsHandle{h: h}, nil
}

type ntfsHandle struct{ h windows.Handle }

// fileAttributeTagInfo and fileIDInfo are FILE_ATTRIBUTE_TAG_INFO and
// FILE_ID_INFO as their pages declare them.
type fileAttributeTagInfo struct {
	FileAttributes uint32
	ReparseTag     uint32
}

type fileIDInfo struct {
	VolumeSerialNumber uint64
	FileID             [16]byte
}

// The GetFinalPathNameByHandleW flags of the reference configuration:
// FILE_NAME_NORMALIZED and VOLUME_NAME_DOS, both 0x0 on its page. The forms
// they give for each kind of name are OI-7.
const finalPathFlags = 0x0

func (f *ntfsHandle) Read(p []byte) (int, error) {
	var n uint32
	if err := windows.ReadFile(f.h, p, &n, nil); err != nil {
		return int(n), err
	}
	if n == 0 && len(p) > 0 {
		return 0, io.EOF
	}
	return int(n), nil
}

// Object reports the handle's attributes (FileAttributeTagInfo), its volume
// serial number and 128-bit file identifier (FileIdInfo) and its final path.
func (f *ntfsHandle) Object() (Object, error) {
	var tag fileAttributeTagInfo
	if err := windows.GetFileInformationByHandleEx(f.h, windows.FileAttributeTagInfo, (*byte)(unsafe.Pointer(&tag)), uint32(unsafe.Sizeof(tag))); err != nil {
		return Object{}, fmt.Errorf("files: FileAttributeTagInfo: %w", err)
	}
	var id fileIDInfo
	if err := windows.GetFileInformationByHandleEx(f.h, windows.FileIdInfo, (*byte)(unsafe.Pointer(&id)), uint32(unsafe.Sizeof(id))); err != nil {
		return Object{}, fmt.Errorf("files: FileIdInfo: %w", err)
	}
	final, err := finalPath(f.h)
	if err != nil {
		return Object{}, err
	}
	return Object{Attributes: Attributes(tag.FileAttributes), VolumeSerial: id.VolumeSerialNumber, ObjectID: id.FileID, FinalPath: final}, nil
}

// finalPath calls GetFinalPathNameByHandleW, again with the size it asks for
// when the buffer is too small: the page says that size includes the
// terminating null, and that a success returns the length without it.
func finalPath(h windows.Handle) (string, error) {
	buf := make([]uint16, windows.MAX_PATH)
	for range 2 {
		n, err := windows.GetFinalPathNameByHandle(h, &buf[0], uint32(len(buf)), finalPathFlags)
		if err != nil {
			return "", fmt.Errorf("files: GetFinalPathNameByHandleW: %w", err)
		}
		if int(n) < len(buf) {
			return windows.UTF16ToString(buf[:n]), nil
		}
		buf = make([]uint16, n)
	}
	return "", errors.New("files: GetFinalPathNameByHandleW: the path keeps growing")
}

func (f *ntfsHandle) Close() error { return windows.CloseHandle(f.h) }
