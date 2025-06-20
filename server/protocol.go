package main

import (
	"bytes"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"

	"github.com/coalaura/up/internal"
	"github.com/patrickmn/go-cache"
	"github.com/vmihailenco/msgpack/v5"
	"golang.org/x/crypto/ssh"
)

var (
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
	log.Printf("request: new request from %s\n", r.RemoteAddr)

	var request internal.AuthRequest

	if err := msgpack.NewDecoder(r.Body).Decode(&request); err != nil {
		w.WriteHeader(http.StatusBadRequest)

		log.Warning("request: failed to decode request")
		log.WarningE(err)

		return
	}

	public, err := DecodeAndAuthorizePublicKey(request.Public, authorized)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)

		log.Warning("request: failed to parse/authorize public key")
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
		PublicKey: public,
	}, cache.DefaultExpiration)

	log.Printf("request: issued challenge to %s\n", r.RemoteAddr)

	w.Header().Set("Content-Type", "application/msgpack")
	msgpack.NewEncoder(w).Encode(challenge)
}

func HandleCompleteRequest(w http.ResponseWriter, r *http.Request, authorized map[string]ssh.PublicKey) {
	log.Printf("complete: new completion from %s\n", r.RemoteAddr)

	var response internal.AuthResponse

	if err := msgpack.NewDecoder(r.Body).Decode(&response); err != nil {
		w.WriteHeader(http.StatusBadRequest)

		log.Warning("complete: failed to decode response")
		log.WarningE(err)

		return
	}

	public, err := DecodeAndAuthorizePublicKey(response.Public, authorized)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)

		log.Warning("complete: failed to parse/authorize public key")
		log.WarningE(err)

		return
	}

	entry, ok := challenges.Get(response.Token)
	if !ok {
		w.WriteHeader(http.StatusBadRequest)

		log.Warning("complete: invalid challenge token")

		return
	}

	challenges.Delete(response.Token)

	challenge := entry.(internal.ChallengeEntry)

	publicA := public.Marshal()
	publicB := challenge.PublicKey.Marshal()

	if !bytes.Equal(publicA, publicB) {
		w.WriteHeader(http.StatusBadRequest)

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
		w.WriteHeader(http.StatusBadRequest)

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
		PublicKey: public,
	}, cache.DefaultExpiration)

	log.Printf("complete: completed auth for %s\n", r.RemoteAddr)

	w.Header().Set("Content-Type", "application/msgpack")
	msgpack.NewEncoder(w).Encode(internal.AuthResult{
		Token: token,
	})
}

func HandleReceiveRequest(w http.ResponseWriter, r *http.Request) {
	log.Printf("receive: request from %s\n", r.RemoteAddr)

	token := r.Header.Get("Authorization")
	if token == "" {
		w.WriteHeader(http.StatusBadRequest)

		log.Warning("receive: missing token")

		return
	}

	if _, ok := sessions.Get(token); !ok {
		w.WriteHeader(http.StatusBadRequest)

		log.Warning("receive: invalid token")

		return
	}

	sessions.Delete(token)

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

	if _, err := os.Stat("files"); os.IsNotExist(err) {
		os.Mkdir("files", 0755)
	}

	target, err := os.OpenFile(filepath.Join("files", name), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)

		log.Warning("receive: failed to open target file")

		return
	}

	defer target.Close()

	read, err := io.Copy(target, part)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)

		log.Warning("receive: failed to copy sent file")

		return
	}

	log.Printf("receive: stored %s from %s (%d bytes)\n", name, r.RemoteAddr, read)

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
		return nil, errors.New("unauthorized key")
	}

	return key, nil
}
