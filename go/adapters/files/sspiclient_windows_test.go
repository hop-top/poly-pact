//go:build windows

package files

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// procInitializeSecurityContextW is the client side of the exchange, used by
// the loopback test only.
var procInitializeSecurityContextW = modsecur32.NewProc("InitializeSecurityContextW")

// loopbackClient is a Negotiate client context of the calling process's own
// credentials: AcquireCredentialsHandleW with SECPKG_CRED_OUTBOUND and no
// principal or authentication data, then InitializeSecurityContextW once per
// leg (InitializeSecurityContextW, Remarks).
type loopbackClient struct {
	cred    secHandle
	ctx     secHandle
	started bool
}

func newLoopbackClient() (*loopbackClient, error) {
	pkg, err := windows.UTF16PtrFromString(negotiatePackage)
	if err != nil {
		return nil, err
	}
	c := &loopbackClient{}
	var expiry int64
	r, _, _ := procAcquireCredentialsHandleW.Call(0, uintptr(unsafe.Pointer(pkg)), secpkgCredOutbound, 0, 0, 0, 0,
		uintptr(unsafe.Pointer(&c.cred)), uintptr(unsafe.Pointer(&expiry)))
	if r != secEOK {
		return nil, fmt.Errorf("AcquireCredentialsHandleW outbound: status 0x%08x", uint32(r))
	}
	return c, nil
}

// step runs one client leg with the server's last token in and returns the
// token for the server and whether the client side is complete.
func (c *loopbackClient) step(in []byte) ([]byte, bool, error) {
	out := make([]byte, maxTokenSize)
	outBuf := secBuffer{cbBuffer: uint32(len(out)), bufferType: secbufferToken, pvBuffer: &out[0]}
	outDesc := secBufferDesc{ulVersion: secbufferVersion, cBuffers: 1, pBuffers: &outBuf}
	var inDesc *secBufferDesc
	var inBuf secBuffer
	if len(in) > 0 {
		inBuf = secBuffer{cbBuffer: uint32(len(in)), bufferType: secbufferToken, pvBuffer: &in[0]}
		inDesc = &secBufferDesc{ulVersion: secbufferVersion, cBuffers: 1, pBuffers: &inBuf}
	}
	var prev uintptr
	if c.started {
		prev = uintptr(unsafe.Pointer(&c.ctx))
	}
	var attrs uint32
	var expiry int64
	r, _, _ := procInitializeSecurityContextW.Call(uintptr(unsafe.Pointer(&c.cred)), prev, 0, 0, 0, securityNativeDrep,
		uintptr(unsafe.Pointer(inDesc)), 0, uintptr(unsafe.Pointer(&c.ctx)), uintptr(unsafe.Pointer(&outDesc)),
		uintptr(unsafe.Pointer(&attrs)), uintptr(unsafe.Pointer(&expiry)))
	c.started = true
	switch r {
	case secEOK:
		return out[:outBuf.cbBuffer], true, nil
	case secIContinueNeeded:
		return out[:outBuf.cbBuffer], false, nil
	}
	return nil, false, fmt.Errorf("InitializeSecurityContextW: status 0x%08x", uint32(r))
}

func (c *loopbackClient) close() {
	if c.started {
		_, _, _ = procDeleteSecurityContext.Call(uintptr(unsafe.Pointer(&c.ctx)))
	}
	_, _, _ = procFreeCredentialsHandle.Call(uintptr(unsafe.Pointer(&c.cred)))
}

// currentUser is the user SID of the process token.
func currentUser() (string, error) {
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return "", err
	}
	return u.User.Sid.String(), nil
}
