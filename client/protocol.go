package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"

	"github.com/coalaura/up/internal"
	"github.com/vmihailenco/msgpack/v5"
	"golang.org/x/crypto/ssh"
)

func RequestChallenge(client *http.Client, hostname, public string) (*internal.AuthChallenge, error) {
	request, err := msgpack.Marshal(internal.AuthRequest{
		Public: public,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %v", err)
	}

	response, err := client.Post(fmt.Sprintf("https://%s/request", hostname), "application/msgpack", bytes.NewReader(request))
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %v", err)
	}

	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return nil, errors.New(response.Status)
	}

	var challenge internal.AuthChallenge

	if err := msgpack.NewDecoder(response.Body).Decode(&challenge); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %v", err)
	}

	return &challenge, nil
}

func CompleteChallenge(client *http.Client, hostname, public string, private ssh.Signer, challenge *internal.AuthChallenge) (*internal.AuthResponse, error) {
	rawChallenge, err := base64.StdEncoding.DecodeString(challenge.Challenge)
	if err != nil {
		return nil, fmt.Errorf("failed to decode challenge: %v", err)
	}

	signature, err := private.Sign(rand.Reader, rawChallenge)
	if err != nil {
		return nil, fmt.Errorf("failed to sign challenge: %v", err)
	}

	request, err := msgpack.Marshal(internal.AuthResponse{
		Token:     challenge.Token,
		Public:    public,
		Format:    signature.Format,
		Signature: base64.StdEncoding.EncodeToString(signature.Blob),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %v", err)
	}

	response, err := client.Post(fmt.Sprintf("https://%s/complete", hostname), "application/msgpack", bytes.NewReader(request))
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %v", err)
	}

	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return nil, errors.New(response.Status)
	}

	var result internal.AuthResponse

	if err := msgpack.NewDecoder(response.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %v", err)
	}

	return &result, nil
}

func SendFile(client *http.Client, hostname, token string, file *os.File) error {
	stat, err := file.Stat()
	if err != nil {
		return fmt.Errorf("failed to stat file: %v", err)
	}

	pReader, pWriter := io.Pipe()

	writer := multipart.NewWriter(pWriter)

	go func() {
		defer pWriter.Close()

		part, err := writer.CreateFormFile("file", filepath.Base(file.Name()))
		if err != nil {
			pWriter.CloseWithError(err)

			return
		}

		if _, err := io.Copy(part, file); err != nil {
			pWriter.CloseWithError(err)

			return
		}

		writer.Close()
	}()

	reader := NewProgressReader("Uploading file", stat.Size(), pReader)

	request, err := http.NewRequest("POST", fmt.Sprintf("https://%s/receive", hostname), reader)
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}

	request.Header.Set("Content-Type", writer.FormDataContentType())
	request.Header.Set("Authorization", token)

	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("failed to send request: %v", err)
	}

	response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return errors.New(response.Status)
	}

	return nil
}
