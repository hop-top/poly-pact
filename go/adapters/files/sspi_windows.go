//go:build windows

package files

import (
	"errors"
	"fmt"
	"runtime"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// golang.org/x/sys/windows exports no SSPI function of secur32.dll other
// than GetUserNameExW and TranslateNameW (doc.go, "Probes"), so the broker
// declares the five it calls. Each page names Secur32.dll.
var (
	modsecur32                    = windows.NewLazySystemDLL("secur32.dll")
	procAcquireCredentialsHandleW = modsecur32.NewProc("AcquireCredentialsHandleW")
	procAcceptSecurityContext     = modsecur32.NewProc("AcceptSecurityContext")
	procQuerySecurityContextToken = modsecur32.NewProc("QuerySecurityContextToken")
	procDeleteSecurityContext     = modsecur32.NewProc("DeleteSecurityContext")
	procFreeCredentialsHandle     = modsecur32.NewProc("FreeCredentialsHandle")
)

// Values the pages state: SECPKG_CRED_INBOUND and SECPKG_CRED_OUTBOUND
// (AcquireCredentialsHandleW), SECBUFFER_EMPTY and SECBUFFER_TOKEN
// (SecBuffer), SEC_E_OK and the SEC_I_ codes (AcceptSecurityContext).
const (
	secpkgCredInbound       = 0x1
	secpkgCredOutbound      = 0x2
	secbufferEmpty          = 0
	secbufferToken          = 2
	secEOK                  = 0x00000000
	secIContinueNeeded      = 0x00090312
	secICompleteNeeded      = 0x00090313
	secICompleteAndContinue = 0x00090314
)

// Values no page read states; each is to probe in the Windows job, where a
// wrong one fails the loopback exchange: SECBUFFER_VERSION, which
// SecBufferDesc requires as ulVersion; SECURITY_NATIVE_DREP, one of the two
// data representations both context functions accept; the size of the
// output token buffer the broker supplies, since it asks for no allocated
// buffer; and "Negotiate" as the name of the package.
const (
	secbufferVersion   = 0
	securityNativeDrep = 0x10
	maxTokenSize       = 64 << 10
	negotiatePackage   = "Negotiate"
)

// secHandle is a CredHandle or a CtxtHandle.
type secHandle struct{ lower, upper uintptr }

// secBuffer and secBufferDesc are SecBuffer and SecBufferDesc as the pages
// declare them.
type secBuffer struct {
	cbBuffer   uint32
	bufferType uint32
	pvBuffer   *byte
}

type secBufferDesc struct {
	ulVersion uint32
	cBuffers  uint32
	pBuffers  *secBuffer
}

// SSPI is the security package of the broker on Windows: its inbound
// credentials for the Negotiate package.
type SSPI struct{ cred secHandle }

// NewSSPI acquires the inbound credentials of the broker's process for the
// Negotiate package (AcquireCredentialsHandleW with SECPKG_CRED_INBOUND and
// no principal or authentication data) and returns the security package of
// the broker. Close frees the credentials.
func NewSSPI() (*SSPI, error) {
	pkg, err := windows.UTF16PtrFromString(negotiatePackage)
	if err != nil {
		return nil, err
	}
	p := &SSPI{}
	var expiry int64
	r, _, _ := procAcquireCredentialsHandleW.Call(0, uintptr(unsafe.Pointer(pkg)), secpkgCredInbound, 0, 0, 0, 0,
		uintptr(unsafe.Pointer(&p.cred)), uintptr(unsafe.Pointer(&expiry)))
	if r != secEOK {
		return nil, fmt.Errorf("files: AcquireCredentialsHandleW: status 0x%08x", uint32(r))
	}
	return p, nil
}

// Close frees the credentials (FreeCredentialsHandle), after every context.
func (p *SSPI) Close() error {
	if r, _, _ := procFreeCredentialsHandle.Call(uintptr(unsafe.Pointer(&p.cred))); r != secEOK {
		return fmt.Errorf("files: FreeCredentialsHandle: status 0x%08x", uint32(r))
	}
	return nil
}

// NewExchange starts the exchange of one connection.
func (p *SSPI) NewExchange() (Exchange, error) { return &sspiExchange{p: p}, nil }

// sspiExchange is one server-side exchange. The DeleteSecurityContext page
// warns that one context handle must not be used in concurrent calls, so
// every call holds mu.
type sspiExchange struct {
	mu      sync.Mutex
	p       *SSPI
	ctx     secHandle
	started bool
	deleted bool
}

var errExchangeDone = errors.New("files: the exchange is closed")

// Accept runs one AcceptSecurityContext leg: the client's token is the first
// input buffer, of type SECBUFFER_TOKEN, and the second is SECBUFFER_EMPTY;
// the context of the first leg is passed back on the next; no context
// requirement is set, and no expiry is asked for, since the page says it may
// be wrong before the last call (profile IA-2). SEC_E_OK completes the
// exchange: the token comes from QuerySecurityContextToken (IA-5) and the
// context is then deleted. SEC_I_CONTINUE_NEEDED returns the output token
// for the client. SEC_I_COMPLETE_NEEDED and SEC_I_COMPLETE_AND_CONTINUE,
// which ask for CompleteAuthToken, are not supported and fail the exchange,
// as does every error (IA-3).
func (e *sspiExchange) Accept(input []byte) ([]byte, Token, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.deleted {
		return nil, nil, errExchangeDone
	}
	if len(input) == 0 {
		return nil, nil, errors.New("files: an empty token")
	}
	in := []secBuffer{
		{cbBuffer: uint32(len(input)), bufferType: secbufferToken, pvBuffer: &input[0]},
		{bufferType: secbufferEmpty},
	}
	inDesc := secBufferDesc{ulVersion: secbufferVersion, cBuffers: uint32(len(in)), pBuffers: &in[0]}
	out := make([]byte, maxTokenSize)
	outBuf := secBuffer{cbBuffer: uint32(len(out)), bufferType: secbufferToken, pvBuffer: &out[0]}
	outDesc := secBufferDesc{ulVersion: secbufferVersion, cBuffers: 1, pBuffers: &outBuf}
	var prev uintptr
	if e.started {
		prev = uintptr(unsafe.Pointer(&e.ctx))
	}
	var attrs uint32
	r, _, _ := procAcceptSecurityContext.Call(uintptr(unsafe.Pointer(&e.p.cred)), prev, uintptr(unsafe.Pointer(&inDesc)), 0,
		securityNativeDrep, uintptr(unsafe.Pointer(&e.ctx)), uintptr(unsafe.Pointer(&outDesc)), uintptr(unsafe.Pointer(&attrs)), 0)
	runtime.KeepAlive(input)
	runtime.KeepAlive(in)
	runtime.KeepAlive(out)
	if r == secEOK || r == secIContinueNeeded || r == secICompleteNeeded || r == secICompleteAndContinue {
		e.started = true
	}
	switch r {
	case secIContinueNeeded:
		return out[:outBuf.cbBuffer], nil, nil
	case secEOK:
	default:
		e.deleteLocked()
		return nil, nil, fmt.Errorf("files: AcceptSecurityContext: status 0x%08x", uint32(r))
	}
	var h windows.Token
	q, _, _ := procQuerySecurityContextToken.Call(uintptr(unsafe.Pointer(&e.ctx)), uintptr(unsafe.Pointer(&h)))
	e.deleteLocked()
	if q != secEOK {
		return nil, nil, fmt.Errorf("files: QuerySecurityContextToken: status 0x%08x", uint32(q))
	}
	tok, err := newWinToken(h)
	if err != nil {
		return nil, nil, err
	}
	return out[:outBuf.cbBuffer], tok, nil
}

// Close deletes the context, partial or complete (DeleteSecurityContext:
// the caller must delete a context that is partial, incomplete, rejected or
// failed).
func (e *sspiExchange) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.deleteLocked()
	return nil
}

func (e *sspiExchange) deleteLocked() {
	if e.started && !e.deleted {
		_, _, _ = procDeleteSecurityContext.Call(uintptr(unsafe.Pointer(&e.ctx)))
	}
	e.deleted = true
}
