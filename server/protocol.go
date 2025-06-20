package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/coalaura/up/internal"
	"github.com/valyala/fasthttp"
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

func HandleChallengeRequest(ctx *fasthttp.RequestCtx, authorized map[string]ssh.PublicKey) {
	var request internal.AuthRequest

	if err := json.Unmarshal(ctx.PostBody(), &request); err != nil {
		ctx.SetStatusCode(fasthttp.StatusBadRequest)

		log.Warning("request: failed to decode request")
		log.WarningE(err)

		return
	}

	public, err := DecodeAndAuthorizePublicKey(request.Public, authorized)
	if err != nil {
		ctx.SetStatusCode(fasthttp.StatusBadRequest)

		log.Warning("request: failed to parse/authorize public key")
		log.WarningE(err)

		return
	}

	challenge, raw, err := internal.FreshChallenge()
	if err != nil {
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)

		log.Warning("request: failed to generate challenge")
		log.WarningE(err)

		return
	}

	challenges.Store(challenge.Token, internal.ChallengeEntry{
		Challenge: raw,
		PublicKey: public,
		Expires:   time.Now().Add(20 * time.Second),
	})

	log.Println("new auth request")

	ctx.SetContentType("application/json")
	json.NewEncoder(ctx).Encode(challenge)
}

func HandleCompleteRequest(ctx *fasthttp.RequestCtx, authorized map[string]ssh.PublicKey) {
	var response internal.AuthResponse

	if err := json.Unmarshal(ctx.PostBody(), &response); err != nil {
		ctx.SetStatusCode(fasthttp.StatusBadRequest)

		log.Warning("complete: failed to decode response")
		log.WarningE(err)

		return
	}

	public, err := DecodeAndAuthorizePublicKey(response.Public, authorized)
	if err != nil {
		ctx.SetStatusCode(fasthttp.StatusBadRequest)

		log.Warning("complete: failed to parse/authorize public key")
		log.WarningE(err)

		return
	}

	entry, ok := challenges.LoadAndDelete(response.Token)
	if !ok {
		ctx.SetStatusCode(fasthttp.StatusBadRequest)

		log.Warning("complete: invalid challenge token")
		log.WarningE(err)

		return
	}

	challenge := entry.(internal.ChallengeEntry)

	if time.Now().After(challenge.Expires) {
		ctx.SetStatusCode(fasthttp.StatusBadRequest)

		log.Warning("complete: challenge expired")
		log.WarningE(err)

		return
	}

	publicA := public.Marshal()
	publicB := challenge.PublicKey.Marshal()

	if !bytes.Equal(publicA, publicB) {
		ctx.SetStatusCode(fasthttp.StatusBadRequest)

		log.Warning("complete: incorrect public key")
		log.WarningE(err)

		return
	}

	if !IsSignatureFormatValid(response.Format) {
		ctx.SetStatusCode(fasthttp.StatusBadRequest)

		log.Warning("complete: unsupported signature format")

		return
	}

	signature, err := base64.StdEncoding.DecodeString(response.Signature)
	if err != nil {
		ctx.SetStatusCode(fasthttp.StatusBadRequest)

		log.Warning("complete: failed to decode signature")
		log.WarningE(err)

		return
	}

	sig := &ssh.Signature{
		Format: response.Format,
		Blob:   signature,
	}

	if err = public.Verify(challenge.Challenge, sig); err != nil {
		ctx.SetStatusCode(fasthttp.StatusBadRequest)

		log.Warning("complete: failed to verify signature")
		log.WarningE(err)

		return
	}

	token, err := RandomToken(64)
	if err != nil {
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)

		log.Warning("complete: failed to create token")
		log.WarningE(err)

		return
	}

	sessions.Store(token, internal.SessionEntry{
		PublicKey: public,
		Expires:   time.Now().Add(5 * time.Minute),
	})

	log.Println("auth completed")

	ctx.SetContentType("application/json")
	json.NewEncoder(ctx).Encode(internal.AuthResult{
		Token: token,
	})
}

func HandleReceiveRequest(ctx *fasthttp.RequestCtx) {
	token := string(ctx.Request.Header.Peek("Authorization"))
	if token == "" {
		ctx.SetStatusCode(fasthttp.StatusBadRequest)

		log.Warning("receive: missing token")

		return
	}

	entry, ok := sessions.LoadAndDelete(token)
	if !ok {
		ctx.SetStatusCode(fasthttp.StatusBadRequest)

		log.Warning("receive: invalid token")

		return
	}

	session := entry.(internal.SessionEntry)

	if time.Now().After(session.Expires) {
		ctx.SetStatusCode(fasthttp.StatusBadRequest)

		log.Warning("receive: session expired")

		return
	}

	form, err := ctx.MultipartForm()
	if err != nil {
		ctx.SetStatusCode(fasthttp.StatusBadRequest)

		log.Warning("receive: failed to parse multipart form")
		log.WarningE(err)

		return
	}

	files := form.File["file"]
	if len(files) == 0 {
		ctx.SetStatusCode(fasthttp.StatusBadRequest)

		log.Warning("receive: no files received")

		return
	}

	header := files[0]
	name := filepath.Base(header.Filename)

	source, err := header.Open()
	if err != nil {
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)

		log.Warning("receive: failed to open sent file")

		return
	}

	defer source.Close()

	if _, err := os.Stat("files"); os.IsNotExist(err) {
		os.Mkdir("files", 0755)
	}

	target, err := os.OpenFile(filepath.Join("files", name), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
	if err != nil {
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)

		log.Warning("receive: failed to open target file")

		return
	}

	defer target.Close()

	if _, err := io.Copy(target, source); err != nil {
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)

		log.Warning("receive: failed to copy sent file")

		return
	}

	ctx.SetStatusCode(fasthttp.StatusOK)
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
