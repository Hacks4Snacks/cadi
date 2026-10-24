package probe

import (
	"errors"
	"net"
	"strconv"
	"strings"
)

// EndpointHost validates an explicit host:port without echoing potential credentials.
func EndpointHost(address string) (string, error) {
	if strings.ContainsAny(address, "/@?# \t\r\n\x00") {
		return "", errors.New("endpoint must be host:port, not a URL, userinfo, or path")
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil || host == "" {
		return "", errors.New("endpoint must contain an explicit host and port")
	}
	number, err := strconv.Atoi(port)
	if err != nil || number < 1 || number > 65535 {
		return "", errors.New("endpoint port must be an integer from 1 to 65535")
	}
	return host, nil
}
