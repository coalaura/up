package server

import (
	"bytes"
	"encoding/base64"
	"errors"
	"io"
	"math"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"github.com/coalaura/up/internal"
	"github.com/patrickmn/go-cache"
	"github.com/vmihailenco/msgpack/v5"
	"golang.org/x/crypto/ssh"
)

var (
	UnauthorizedErr  = errors.New("unauthorized key")
	SignatureFormats = map[string]bool{
		"ssh-ed25519":         true,
		"ssh-rsa":             true,
		"rsa-sha2-256":        true,
		"rsa-sha2-512":        true,
		"ecdsa-sha2-nistp256": true,
		"ecdsa-sha2-nistp384": true,
		"ecdsa-sha2-nistp521": true,
	}
)

func IsSignatureFormatValid(format string) bool {
	return SignatureFormats[format]
}

func HandleChallengeRequest(w http.ResponseWriter, r *http.Request, authorized map[string]ssh.PublicKey) {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)

		log.Warning("request: failed to split remote ip")
		log.WarningE(err)

		return
	}

	log.Printf("request: received new request from %s\n", ip)

	current, pass, fail := rates.Inc(ip)
	defer fail()

	if current > MaxClientParallel || current == 0 {
		w.WriteHeader(http.StatusTooManyRequests)

		log.Warning("request: too many requests")
		log.WarningE(err)

		return
	}

	var request internal.AuthRequest

	reader := io.LimitReader(r.Body, 4096)

	if err := msgpack.NewDecoder(reader).Decode(&request); err != nil {
		w.WriteHeader(http.StatusBadRequest)

		log.Warning("request: failed to decode request payload")
		log.WarningE(err)

		return
	}

	public, err := DecodeAndAuthorizePublicKey(request.Public, authorized)
	if err != nil {
		if err == UnauthorizedErr {
			w.WriteHeader(http.StatusUnauthorized)
		} else {
			w.WriteHeader(http.StatusBadRequest)
		}

		log.Warning("request: failed to parse or authorize public key")
		log.WarningE(err)

		return
	}

	challenge, raw, err := internal.FreshChallenge()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)

		log.Warning("request: failed to generate challenge")
		log.WarningE(err)

		return
	}

	challenges.Set(challenge.Token, internal.ChallengeEntry{
		Challenge: raw,
		Client:    ip,
		PublicKey: public,
	}, cache.DefaultExpiration)

	pass()

	log.Printf("request: issued challenge to %s\n", ip)

	w.Header().Set("Content-Type", "application/msgpack")
	msgpack.NewEncoder(w).Encode(challenge)
}

func HandleCompleteRequest(w http.ResponseWriter, r *http.Request, authorized map[string]ssh.PublicKey) {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)

		log.Warning("complete: failed to split remote ip")
		log.WarningE(err)

		return
	}

	log.Printf("complete: received completion from %s\n", ip)

	current, pass, fail := rates.Inc(ip)
	defer fail()

	if current > MaxClientParallel || current == 0 {
		w.WriteHeader(http.StatusTooManyRequests)

		log.Warning("request: too many requests")
		log.WarningE(err)

		return
	}

	var response internal.AuthResponse

	reader := io.LimitReader(r.Body, 4096)

	if err := msgpack.NewDecoder(reader).Decode(&response); err != nil {
		w.WriteHeader(http.StatusBadRequest)

		log.Warning("complete: failed to decode response payload")
		log.WarningE(err)

		return
	}

	public, err := DecodeAndAuthorizePublicKey(response.Public, authorized)
	if err != nil {
		if err == UnauthorizedErr {
			w.WriteHeader(http.StatusUnauthorized)
		} else {
			w.WriteHeader(http.StatusBadRequest)
		}

		log.Warning("complete: failed to parse or authorize public key")
		log.WarningE(err)

		return
	}

	entry, ok := challenges.Get(response.Token)
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)

		log.Warning("complete: invalid challenge token")

		return
	}

	challenges.Delete(response.Token)

	challenge := entry.(internal.ChallengeEntry)

	if challenge.Client != ip {
		w.WriteHeader(http.StatusUnauthorized)

		log.Warning("complete: incorrect client ip")

		return
	}

	publicA := public.Marshal()
	publicB := challenge.PublicKey.Marshal()

	if !bytes.Equal(publicA, publicB) {
		w.WriteHeader(http.StatusUnauthorized)

		log.Warning("complete: incorrect public key")

		return
	}

	if !IsSignatureFormatValid(response.Format) {
		w.WriteHeader(http.StatusBadRequest)

		log.Warning("complete: unsupported signature format")

		return
	}

	signature, err := base64.StdEncoding.DecodeString(response.Signature)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)

		log.Warning("complete: failed to decode signature")
		log.WarningE(err)

		return
	}

	sig := &ssh.Signature{
		Format: response.Format,
		Blob:   signature,
	}

	if err = public.Verify(challenge.Challenge, sig); err != nil {
		w.WriteHeader(http.StatusUnauthorized)

		log.Warning("complete: failed to verify signature")
		log.WarningE(err)

		return
	}

	token, err := RandomToken(64)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)

		log.Warning("complete: failed to create token")
		log.WarningE(err)

		return
	}

	sessions.Set(token, internal.SessionEntry{
		Client: ip,
	}, cache.DefaultExpiration)

	pass()

	log.Printf("complete: authentication completed for %s\n", ip)

	w.Header().Set("Content-Type", "application/msgpack")
	msgpack.NewEncoder(w).Encode(internal.AuthResult{
		Token: token,
	})
}

func HandleReceiveRequest(w http.ResponseWriter, r *http.Request) {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)

		log.Warning("receive: failed to split remote ip")
		log.WarningE(err)

		return
	}

	log.Printf("receive: received request from %s\n", ip)

	token := r.Header.Get("Authorization")
	if token == "" {
		w.WriteHeader(http.StatusUnauthorized)

		log.Warning("receive: missing token")

		return
	}

	entry, ok := sessions.Get(token)
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)

		log.Warning("receive: invalid token")

		return
	}

	sessions.Delete(token)

	current, _, fail := rates.Inc(ip)
	defer fail()

	if current > MaxClientParallel || current == 0 {
		w.WriteHeader(http.StatusTooManyRequests)

		log.Warning("receive: too many requests")
		log.WarningE(err)

		return
	}

	session := entry.(internal.SessionEntry)

	if session.Client != ip {
		w.WriteHeader(http.StatusUnauthorized)

		log.Warning("receive: incorrect client ip")

		return
	}

	t0 := time.Now()

	reader, err := r.MultipartReader()
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)

		log.Warning("receive: failed to open multipart form")
		log.WarningE(err)

		return
	}

	part, err := reader.NextPart()
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)

		log.Warning("receive: failed to read multipart form")
		log.WarningE(err)

		return
	}

	if part.FormName() != "file" {
		w.WriteHeader(http.StatusBadRequest)

		log.Warning("receive: invalid multipart part")
		log.WarningE(err)

		return
	}

	name := filepath.Base(part.FileName())
	name = SanitizeFilename(name)

	if name == "" {
		w.WriteHeader(http.StatusBadRequest)

		log.Warning("receive: invalid or missing filename")
		log.WarningE(err)

		return
	}

	if _, err := os.Stat("files"); os.IsNotExist(err) {
		os.Mkdir("files", 0700)
	}

	target, err := os.OpenFile(filepath.Join("files", name), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)

		log.Warning("receive: failed to open target file")

		return
	}

	defer target.Close()

	read, err := io.Copy(target, part)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)

		log.Warning("receive: failed to save uploaded file")

		return
	}

	log.Printf("receive: stored file %s from %s (%d bytes, took %s)\n", name, ip, read, RoundSince(time.Since(t0)))

	w.WriteHeader(http.StatusOK)
}

func DecodeAndAuthorizePublicKey(public string, authorized map[string]ssh.PublicKey) (ssh.PublicKey, error) {
	data, err := base64.StdEncoding.DecodeString(public)
	if err != nil {
		return nil, err
	}

	key, err := ssh.ParsePublicKey(data)
	if err != nil {
		return nil, err
	}

	if _, ok := authorized[string(key.Marshal())]; !ok {
		return nil, UnauthorizedErr
	}

	return key, nil
}

func SanitizeFilename(name string) string {
	if name == "" {
		return ""
	}

	var (
		bad     bool
		cleaned strings.Builder
	)

	for _, r := range name {
		if r >= 32 && r != 127 && !unicode.IsControl(r) {
			cleaned.WriteRune(r)

			bad = false
		} else if !bad {
			cleaned.WriteRune('_')

			bad = true
		}
	}

	return cleaned.String()
}

func RoundSince(since time.Duration) time.Duration {
	exp := int(math.Log10(float64(since)))
	by := time.Duration(math.Pow(10, max(0, float64(exp)-2)))

	return since.Round(by)
}
