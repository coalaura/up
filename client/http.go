package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

func GetHttp2Transport(verify func(tls.ConnectionState) error) *http.Transport {
	return &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion:         tls.VersionTLS13,
			NextProtos:         []string{"h2"},
			InsecureSkipVerify: true,
			VerifyConnection:   verify,
		},
		Dial: (&net.Dialer{
			Timeout: 5 * time.Second,
		}).Dial,
		TLSHandshakeTimeout: 5 * time.Second,
		IdleConnTimeout:     10 * time.Second,
		ForceAttemptHTTP2:   true,
	}
}

func GetHttp3Transport(verify func(tls.ConnectionState) error) *http3.Transport {
	return &http3.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion:         tls.VersionTLS13,
			NextProtos:         []string{http3.NextProtoH3},
			InsecureSkipVerify: true,
			VerifyConnection:   verify,
		},
		QUICConfig: &quic.Config{
			HandshakeIdleTimeout: 5 * time.Second,
			MaxIdleTimeout:       10 * time.Second,
		},
	}
}

func NewHttpClient(verify func(tls.ConnectionState) error, useHttp3 bool) *http.Client {
	var transport http.RoundTripper

	if useHttp3 {
		transport = GetHttp2Transport(verify)
	} else {
		transport = GetHttp3Transport(verify)
	}

	return &http.Client{
		Transport: transport,
	}
}

func ResolveTLSCertificateHttp2(addr string) (*x509.Certificate, string, error) {
	transport := GetHttp2Transport(nil)

	conn, err := tls.DialWithDialer(&net.Dialer{
		Timeout: 5 * time.Second,
	}, "tcp", addr, transport.TLSClientConfig)
	if err != nil {
		return nil, "", err
	}

	defer conn.Close()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, "", errors.New("no peer certificates")
	}

	return state.PeerCertificates[0], state.ServerName, nil
}

func ResolveTLSCertificateHttp3(addr string) (*x509.Certificate, string, error) {
	transport := GetHttp3Transport(nil)

	conn, err := quic.DialAddr(context.Background(), addr, transport.TLSClientConfig, transport.QUICConfig)
	if err != nil {
		return nil, "", err
	}

	defer conn.CloseWithError(quic.ApplicationErrorCode(0), "")

	state := conn.ConnectionState().TLS
	if len(state.PeerCertificates) == 0 {
		return nil, "", errors.New("no peer certificates")
	}

	return state.PeerCertificates[0], state.ServerName, nil
}

func StripPort(hostname string) (string, error) {
	host, _, err := net.SplitHostPort(hostname)

	return host, err
}

func EnsurePort(hostname string) (string, error) {
	host, port, err := net.SplitHostPort(hostname)
	if err != nil {
		return "", err
	}

	if port == "" {
		port = "443"
	}

	return fmt.Sprintf("%s:%s", host, port), err
}
