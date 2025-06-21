package client

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

type PinnedCertificate struct {
	Name        string
	Fingerprint string
}

type CertificateStore struct {
	path   string
	pinned []PinnedCertificate
	mx     sync.RWMutex
}

func (cs *CertificateStore) IsPinned(name, fingerprint string) bool {
	cs.mx.RLock()
	defer cs.mx.RUnlock()

	if len(cs.pinned) == 0 {
		return false
	}

	for _, pin := range cs.pinned {
		if pin.Fingerprint == fingerprint && pin.Name == name {
			return true
		}
	}

	return false
}

func (cs *CertificateStore) Pin(name, fingerprint string) error {
	cs.mx.Lock()
	defer cs.mx.Unlock()

	pin := PinnedCertificate{
		Name:        name,
		Fingerprint: fingerprint,
	}

	file, err := os.OpenFile(cs.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}

	defer file.Close()

	if _, err = file.WriteString(fmt.Sprintf("%s %s\n", name, fingerprint)); err != nil {
		return err
	}

	cs.pinned = append(cs.pinned, pin)

	return nil
}

func LoadCertificateStore() (*CertificateStore, error) {
	path, err := PinnedCertificatesPath()
	if err != nil {
		return nil, err
	}

	store := &CertificateStore{
		path: path,
	}

	if _, err := os.Stat(path); os.IsNotExist(err) {
		return store, nil
	}

	contents, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var index int

	for line := range bytes.SplitSeq(contents, []byte("\n")) {
		index++

		if len(line) == 0 {
			continue
		}

		fields := bytes.Fields(line)
		if len(fields) != 2 {
			return nil, fmt.Errorf("Invalid pinned certificate on line %d\n", index)
		}

		name := bytes.ToLower(fields[0])
		fingerprint := bytes.ToLower(fields[1])

		if len(fingerprint) < 64 {
			return nil, fmt.Errorf("Invalid fingerprint on line %d\n", index)
		}

		store.pinned = append(store.pinned, PinnedCertificate{
			Name:        string(name),
			Fingerprint: string(fingerprint),
		})
	}

	return store, nil
}

func PinnedCertificatesPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}

	return filepath.Join(home, ".up"), nil
}

func CertificateFingerprint(certificate *x509.Certificate) string {
	sum := sha256.Sum256(certificate.Raw)
	algo := strings.ToLower(certificate.PublicKeyAlgorithm.String())

	return fmt.Sprintf("%s-%s", algo, hex.EncodeToString(sum[:]))
}

func PreFetchServerCertificate(store *CertificateStore, hostname string, useHttp3 bool) error {
	addr, err := EnsurePort(hostname)
	if err != nil {
		return err
	}

	var (
		name        string
		certificate *x509.Certificate
	)

	if useHttp3 {
		certificate, name, err = ResolveTLSCertificateHttp3(addr)
	} else {
		certificate, name, err = ResolveTLSCertificateHttp2(addr)
	}

	if err != nil {
		return err
	}

	if certificate.Subject.CommonName != "up" {
		return errors.New("invalid certificate subject")
	}

	fingerprint := CertificateFingerprint(certificate)

	if store.IsPinned(name, fingerprint) {
		return nil
	}

	log.Printf("Server fingerprint for %s: %s\n", name, fingerprint)
	log.Print("Accept? [y/N]: ")

	var confirm string

	fmt.Scanln(&confirm)

	if strings.ToLower(strings.TrimSpace(confirm)) != "y" {
		return errors.New("certificate rejected")
	}

	return store.Pin(name, fingerprint)
}

func NewPinnedClient(store *CertificateStore, useHttp3 bool) *http.Client {
	return NewHttpClient(func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return errors.New("missing certificate")
		}

		certificate := cs.PeerCertificates[0]

		if certificate.Subject.CommonName != "up" {
			return errors.New("invalid certificate subject")
		}

		name := cs.ServerName
		fingerprint := CertificateFingerprint(certificate)

		if !store.IsPinned(name, fingerprint) {
			return errors.New("unknown certificate")
		}

		return nil
	}, useHttp3)
}
