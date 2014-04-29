/*
 * Package socks implements a SOCKS5 proxy client.
*/
package socks

import (
	"errors"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"
)

const Socks5Connect byte			= 0x01
const Socks5IPv4Addr byte			= 0x01
const Socks5DomainName byte			= 0x03
const Socks5IPv6Addr byte			= 0x04
const Socks5NoAuthentication byte	= 0x00
const Socks5RequestGranted byte		= 0x00
const Socks5Version byte			= 0x05


// DialSocks5Timeout dials to targetAddr through the specified proxy.  The
// "proxy" argument should be in the format expected by net.SplitHostPort.  The
// connection's deadline will be set to time.Now() + timeout.  Authentication
// is not supported.
func DialSocks5Timeout(proxy, targetAddr string, timeout time.Duration) (conn net.Conn, err error) {
	var resp [18]byte

	now := time.Now()
	conn, err = net.DialTimeout("tcp", proxy, timeout)
	if err != nil {
		return nil, err
	}

	// use the time.Now() taken at the beginning of the function
	err = conn.SetDeadline(now.Add(timeout))
	if err != nil {
		return nil, err
	}

	// initial greeting; only offer NoAuthentication
	_, err = conn.Write([]byte{Socks5Version, 1, Socks5NoAuthentication})
	if err != nil {
		return nil, err
	}

	// server responds with the chosen auth method
	_, err = io.ReadFull(conn, resp[:2])
	if err != nil {
		return nil, err
	}
	if resp[0] != Socks5Version {
		return nil, errors.New("SOCKS proxy server does not support SOCKS5")
	}
	if resp[1] != Socks5NoAuthentication {
		return nil, fmt.Errorf("SOCKS authentication method negotiation failed; expected %x, got %x", Socks5NoAuthentication, resp[1])
	}

	// connection request
	host, port, err := splitHostPort(targetAddr)
	if err != nil {
		return nil, err
	}
	hostBytes := []byte(host)
	if len(hostBytes) > 0xFF {
		return nil, fmt.Errorf("hostname %s over maximum length %d", host, 0xFF)
	}
	req := []byte{Socks5Version, Socks5Connect, 0x00,
				  Socks5DomainName, byte(len(hostBytes))}
	req = append(req, hostBytes...)
	req = append(req, htons(port)...)
	_, err = conn.Write(req)
	if err != nil {
		return nil, err
	}

	// server responds with OK / failure
	_, err = io.ReadFull(conn, resp[:4])
	if err != nil {
		return nil, err
	}
	if resp[0] != Socks5Version {
		return nil, fmt.Errorf("SOCKS version %x is not 5", resp[0])
	}
	if resp[1] != Socks5RequestGranted {
		return nil, fmt.Errorf("could not complete SOCKS5 connection: %x", resp[1])
	}
	if resp[2] != 0x00 {
		return nil, fmt.Errorf("SOCKS5: reserved byte %x is not 0x00", resp[2])
	}
	switch resp[3] {
		case Socks5IPv4Addr:
			_, err = io.ReadFull(conn, resp[:4+2])
		case Socks5IPv6Addr:
			_, err = io.ReadFull(conn, resp[:16+2])
		default:
			return nil, fmt.Errorf("invalid address type %x in CONNECT response", resp[3])
	}
	return conn, err
}

func htons(n uint16) []byte {
	var d [2]byte
	binary.BigEndian.PutUint16(d[:], n)
	return d[:]
}

func splitHostPort(addr string) (host string, port uint16, err error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0, err
	}
	portInt, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return "", 0, err
	}
	port = uint16(portInt)
	return host, port, nil
}
