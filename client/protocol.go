package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"

	"github.com/coalaura/up/internal"
	"golang.org/x/crypto/ssh"
)

func RequestChallenge(target, public string) (*internal.AuthChallenge, error) {
	request, err := json.Marshal(internal.AuthRequest{
		Public: public,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %v", err)
	}

	response, err := http.Post(fmt.Sprintf("%s/request", target), "application/json", bytes.NewReader(request))
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %v", err)
	}

	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return nil, errors.New(response.Status)
	}

	var challenge internal.AuthChallenge

	if err := json.NewDecoder(response.Body).Decode(&challenge); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %v", err)
	}

	return &challenge, nil
}

func CompleteChallenge(target, public string, private ssh.Signer, challenge *internal.AuthChallenge) (*internal.AuthResponse, error) {
	rawChallenge, err := base64.StdEncoding.DecodeString(challenge.Challenge)
	if err != nil {
		return nil, fmt.Errorf("failed to decode challenge: %v", err)
	}

	signature, err := private.Sign(rand.Reader, rawChallenge)
	if err != nil {
		return nil, fmt.Errorf("failed to sign challenge: %v", err)
	}

	request, err := json.Marshal(internal.AuthResponse{
		Token:     challenge.Token,
		Public:    public,
		Format:    signature.Format,
		Signature: base64.StdEncoding.EncodeToString(signature.Blob),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %v", err)
	}

	response, err := http.Post(fmt.Sprintf("%s/complete", target), "application/json", bytes.NewReader(request))
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %v", err)
	}

	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return nil, errors.New(response.Status)
	}

	var result internal.AuthResponse

	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %v", err)
	}

	return &result, nil
}

func SendFile(target, token string, file *os.File) error {
	var buf bytes.Buffer

	writer := multipart.NewWriter(&buf)

	part, err := writer.CreateFormFile("file", filepath.Base(file.Name()))
	if err != nil {
		return fmt.Errorf("failed to create form file: %v", err)
	}

	if _, err := io.Copy(part, file); err != nil {
		return fmt.Errorf("failed to copy file: %v", err)
	}

	writer.Close()

	request, err := http.NewRequest("POST", fmt.Sprintf("%s/receive", target), &buf)
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}

	request.Header.Set("Content-Type", writer.FormDataContentType())
	request.Header.Set("Authorization", token)

	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return fmt.Errorf("failed to send request: %v", err)
	}

	response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return errors.New(response.Status)
	}

	return nil
}
