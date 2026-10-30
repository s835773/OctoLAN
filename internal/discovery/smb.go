package discovery

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"time"
	"unicode/utf16"

	"github.com/s835773/OctoLAN/internal/model"
)

// ProbeSMB checks SMBv1 support and pulls the host's Windows version,
// NetBIOS/DNS names and domain from the anonymous NTLM challenge. No
// credentials are sent; this is what any client sees before logging in.
func ProbeSMB(ctx context.Context, ip netip.Addr, timeout time.Duration) *model.SMBInfo {
	info := &model.SMBInfo{}
	ok := false
	if smb1Supported(ctx, ip, timeout) {
		info.SMB1 = true
		ok = true
	}
	if smb2Probe(ctx, ip, timeout, info) {
		ok = true
	}
	if !ok {
		return nil
	}
	return info
}

func smbDial(ctx context.Context, ip netip.Addr, timeout time.Duration) (net.Conn, error) {
	d := net.Dialer{Timeout: timeout}
	c, err := d.DialContext(ctx, "tcp4", netip.AddrPortFrom(ip, 445).String())
	if err != nil {
		return nil, err
	}
	_ = c.SetDeadline(time.Now().Add(timeout + 2*time.Second))
	return c, nil
}

func nbssWrite(w io.Writer, msg []byte) error {
	hdr := []byte{0, byte(len(msg) >> 16), byte(len(msg) >> 8), byte(len(msg))}
	_, err := w.Write(append(hdr, msg...))
	return err
}

func nbssRead(r io.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := int(hdr[1])<<16 | int(hdr[2])<<8 | int(hdr[3])
	if n > 1<<20 {
		return nil, fmt.Errorf("smb frame too large")
	}
	buf := make([]byte, n)
	_, err := io.ReadFull(r, buf)
	return buf, err
}

// smb1Supported sends an SMB1 NEGOTIATE offering only "NT LM 0.12".
func smb1Supported(ctx context.Context, ip netip.Addr, timeout time.Duration) bool {
	c, err := smbDial(ctx, ip, timeout)
	if err != nil {
		return false
	}
	defer c.Close()
	dialects := []byte("\x02NT LM 0.12\x00")
	msg := make([]byte, 32, 32+3+len(dialects))
	copy(msg, []byte{0xff, 'S', 'M', 'B', 0x72})
	msg[9] = 0x18                                   // flags: case-insensitive, canonical paths
	binary.LittleEndian.PutUint16(msg[10:], 0xc001) // flags2: unicode, NT status, long names
	binary.LittleEndian.PutUint16(msg[26:], 0xfeff) // PID
	msg = append(msg, 0)                            // word count
	msg = binary.LittleEndian.AppendUint16(msg, uint16(len(dialects)))
	msg = append(msg, dialects...)
	if nbssWrite(c, msg) != nil {
		return false
	}
	resp, err := nbssRead(c)
	if err != nil || len(resp) < 37 || !bytes.Equal(resp[:4], []byte{0xff, 'S', 'M', 'B'}) || resp[4] != 0x72 {
		return false
	}
	if binary.LittleEndian.Uint32(resp[5:9]) != 0 {
		return false
	}
	return resp[32] > 0 && binary.LittleEndian.Uint16(resp[33:35]) != 0xffff
}

func smb2Header(cmd uint16, msgID uint64) []byte {
	h := make([]byte, 64)
	copy(h, []byte{0xfe, 'S', 'M', 'B'})
	binary.LittleEndian.PutUint16(h[4:], 64)
	binary.LittleEndian.PutUint16(h[12:], cmd)
	binary.LittleEndian.PutUint16(h[14:], 1) // credits requested
	binary.LittleEndian.PutUint64(h[24:], msgID)
	binary.LittleEndian.PutUint32(h[32:], 0xfeff)
	return h
}

func smb2Probe(ctx context.Context, ip netip.Addr, timeout time.Duration, info *model.SMBInfo) bool {
	c, err := smbDial(ctx, ip, timeout)
	if err != nil {
		return false
	}
	defer c.Close()

	// NEGOTIATE
	dialects := []uint16{0x0202, 0x0210, 0x0300, 0x0302}
	neg := smb2Header(0x0000, 0)
	body := make([]byte, 36)
	binary.LittleEndian.PutUint16(body[0:], 36)
	binary.LittleEndian.PutUint16(body[2:], uint16(len(dialects)))
	binary.LittleEndian.PutUint16(body[4:], 1) // signing enabled
	_, _ = rand.Read(body[12:28])              // client GUID
	for _, d := range dialects {
		body = binary.LittleEndian.AppendUint16(body, d)
	}
	if nbssWrite(c, append(neg, body...)) != nil {
		return false
	}
	resp, err := nbssRead(c)
	if err != nil || len(resp) < 72 || !bytes.Equal(resp[:4], []byte{0xfe, 'S', 'M', 'B'}) {
		return false
	}
	if binary.LittleEndian.Uint32(resp[8:12]) != 0 {
		return false
	}
	secMode := binary.LittleEndian.Uint16(resp[66:68])
	info.SigningReq = secMode&0x2 != 0
	switch binary.LittleEndian.Uint16(resp[68:70]) {
	case 0x0202:
		info.Dialect = "SMB 2.0.2"
	case 0x0210:
		info.Dialect = "SMB 2.1"
	case 0x0300:
		info.Dialect = "SMB 3.0"
	case 0x0302:
		info.Dialect = "SMB 3.0.2"
	case 0x0311:
		info.Dialect = "SMB 3.1.1"
	default:
		info.Dialect = fmt.Sprintf("0x%04x", binary.LittleEndian.Uint16(resp[68:70]))
	}

	// SESSION_SETUP carrying an NTLMSSP NEGOTIATE, wrapped in SPNEGO.
	ss := smb2Header(0x0001, 1)
	token := spnegoInit(ntlmNegotiate())
	sb := make([]byte, 24)
	binary.LittleEndian.PutUint16(sb[0:], 25)
	sb[3] = 1 // signing enabled
	binary.LittleEndian.PutUint16(sb[12:], 64+24)
	binary.LittleEndian.PutUint16(sb[14:], uint16(len(token)))
	if nbssWrite(c, append(append(ss, sb...), token...)) != nil {
		return true
	}
	resp, err = nbssRead(c)
	if err != nil {
		return true
	}
	if i := bytes.Index(resp, []byte("NTLMSSP\x00")); i >= 0 {
		parseNTLMChallenge(resp[i:], info)
	}
	return true
}

func ntlmNegotiate() []byte {
	m := []byte("NTLMSSP\x00")
	m = binary.LittleEndian.AppendUint32(m, 1)
	// UNICODE|OEM|REQUEST_TARGET|NTLM|ALWAYS_SIGN|EXTENDED_SESSIONSECURITY|
	// TARGET_INFO|VERSION|128|KEY_EXCH|56
	m = binary.LittleEndian.AppendUint32(m, 0xe2888207|0x02000000)
	m = append(m, make([]byte, 16)...)            // domain + workstation fields
	m = append(m, 10, 0, 0x61, 0x4a, 0, 0, 0, 15) // version 10.0.19041, NTLM rev 15
	return m
}

// derLen encodes an ASN.1 DER length.
func derLen(n int) []byte {
	switch {
	case n < 0x80:
		return []byte{byte(n)}
	case n < 0x100:
		return []byte{0x81, byte(n)}
	default:
		return []byte{0x82, byte(n >> 8), byte(n)}
	}
}

func der(tag byte, content []byte) []byte {
	return append(append([]byte{tag}, derLen(len(content))...), content...)
}

func spnegoInit(ntlm []byte) []byte {
	ntlmOID := []byte{0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a}
	mechTypes := der(0xa0, der(0x30, ntlmOID))
	mechToken := der(0xa2, der(0x04, ntlm))
	negTokenInit := der(0xa0, der(0x30, append(mechTypes, mechToken...)))
	spnegoOID := []byte{0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02}
	return der(0x60, append(spnegoOID, negTokenInit...))
}

func parseNTLMChallenge(b []byte, info *model.SMBInfo) {
	if len(b) < 48 || binary.LittleEndian.Uint32(b[8:12]) != 2 {
		return
	}
	flags := binary.LittleEndian.Uint32(b[20:24])
	tiLen := int(binary.LittleEndian.Uint16(b[40:42]))
	tiOff := int(binary.LittleEndian.Uint32(b[44:48]))
	if flags&0x02000000 != 0 && len(b) >= 56 {
		major, minor := b[48], b[49]
		build := binary.LittleEndian.Uint16(b[50:52])
		info.OSMajorMinor = fmt.Sprintf("%d.%d", major, minor)
		info.OSBuild = fmt.Sprintf("%d", build)
	}
	if tiOff <= 0 || tiOff+tiLen > len(b) {
		return
	}
	ti := b[tiOff : tiOff+tiLen]
	for len(ti) >= 4 {
		id := binary.LittleEndian.Uint16(ti[0:2])
		l := int(binary.LittleEndian.Uint16(ti[2:4]))
		if id == 0 || 4+l > len(ti) {
			break
		}
		v := utf16le(ti[4 : 4+l])
		switch id {
		case 1:
			info.NetBIOSName = v
		case 2:
			info.NetBIOSDom = v
		case 3:
			info.DNSName = v
		case 4:
			info.DNSDomain = v
		}
		ti = ti[4+l:]
	}
}

func utf16le(b []byte) string {
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(b[i*2:])
	}
	return string(utf16.Decode(u))
}

// WindowsVersion maps an NTLM version/build to a product name and whether
// it is past end of support (as of late 2026).
func WindowsVersion(majorMinor, build string, serverHint bool) (name string, eol bool) {
	b := 0
	fmt.Sscanf(build, "%d", &b)
	switch majorMinor {
	case "5.0":
		return "Windows 2000", true
	case "5.1":
		return "Windows XP", true
	case "5.2":
		return "Windows Server 2003 / XP x64", true
	case "6.0":
		return pick(serverHint, "Windows Server 2008", "Windows Vista"), true
	case "6.1":
		return pick(serverHint, "Windows Server 2008 R2", "Windows 7"), true
	case "6.2":
		return pick(serverHint, "Windows Server 2012", "Windows 8"), true
	case "6.3":
		return pick(serverHint, "Windows Server 2012 R2", "Windows 8.1"), true
	case "10.0":
		switch {
		case b >= 26100 && serverHint:
			return "Windows Server 2025", false
		case b >= 26200:
			return "Windows 11 25H2", false
		case b >= 26100:
			return "Windows 11 24H2", false
		case b >= 22631:
			return "Windows 11 23H2", false
		case b >= 22621:
			return "Windows 11 22H2", true
		case b >= 22000:
			return "Windows 11 21H2", true
		case b == 20348:
			return "Windows Server 2022", false
		case b >= 19041:
			return "Windows 10 " + win10Release(b), true
		case b == 17763:
			return pick(serverHint, "Windows Server 2019", "Windows 10 1809 (LTSC 2019)"), false
		case b == 14393:
			return pick(serverHint, "Windows Server 2016", "Windows 10 1607 (LTSB 2016)"), !serverHint
		case b >= 10240:
			return "Windows 10 " + win10Release(b), true
		}
		return "Windows 10/11 / Server 2016+", false
	}
	return "Windows " + majorMinor, false
}

func win10Release(b int) string {
	switch {
	case b >= 19045:
		return "22H2"
	case b >= 19044:
		return "21H2"
	case b >= 19043:
		return "21H1"
	case b >= 19042:
		return "20H2"
	case b >= 19041:
		return "2004"
	case b >= 18362:
		return "1903/1909"
	case b >= 17134:
		return "1803"
	case b >= 16299:
		return "1709"
	case b >= 15063:
		return "1703"
	}
	return fmt.Sprintf("build %d", b)
}

func pick(c bool, a, b string) string {
	if c {
		return a
	}
	return b
}
