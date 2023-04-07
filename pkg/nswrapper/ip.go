package nswrapper

import (
	"bytes"
	"errors"
	"net"
	"net/http"
	"strings"
)

// Returns the type of IP address (A or AAAA) for a given IP address.
// If the IP address is not valid, an empty string is returned.
func GetIPType(ipAddr string) string {
	ip := net.ParseIP(ipAddr)
	if ip == nil {
		return ""
	}
	if ip.To4() != nil {
		return "A"
	}
	if ip.To16() != nil {
		return "AAAA"
	}
	return ""
}

// Returns the public IP address of the client making the HTTP request.
// If a public IP address cannot be found, an error is returned.
func GetCallerIP(r *http.Request) (string, error) {
	for _, h := range []string{"X-Real-Ip", "X-Forwarded-For"} {
		addresses := strings.Split(r.Header.Get(h), ",")
		for i := len(addresses) - 1; i >= 0; i-- {
			ip := strings.TrimSpace(addresses[i])
			realIP := net.ParseIP(ip)
			if realIP == nil {
				continue
			}
			if realIP.IsGlobalUnicast() && !isPrivateSubnet(realIP) {
				return ip, nil
			}
		}
	}
	return "", errors.New("unable to determine caller IP address")
}

func ShrinkUserAgent(agent string) string {
	parts := strings.Fields(agent)
	return parts[0]
}

type IPRange struct {
	start, end net.IP
}

func isInRange(r IPRange, ip net.IP) bool {
	return bytes.Compare(ip, r.start) >= 0 && bytes.Compare(ip, r.end) < 0
}

var privateRanges = []IPRange{
	{start: net.ParseIP("10.0.0.0"), end: net.ParseIP("10.255.255.255")},
	{start: net.ParseIP("100.64.0.0"), end: net.ParseIP("100.127.255.255")},
	{start: net.ParseIP("172.16.0.0"), end: net.ParseIP("172.31.255.255")},
	{start: net.ParseIP("192.0.0.0"), end: net.ParseIP("192.0.0.255")},
	{start: net.ParseIP("192.168.0.0"), end: net.ParseIP("192.168.255.255")},
	{start: net.ParseIP("198.18.0.0"), end: net.ParseIP("198.19.255.255")},
}

// Checks whether the passed IP address is in a private subnet.
// Returns true if the IP address is in a private subnet.
func isPrivateSubnet(ipAddress net.IP) bool {
	if ipCheck := ipAddress.To4(); ipCheck == nil {
		return false
	}
	for _, r := range privateRanges {
		if isInRange(r, ipAddress) {
			return true
		}
	}
	return false
}
