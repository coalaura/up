package main

import (
	"io"
)

type ProgressReader struct {
	io.Reader
	label string
	total int64
	read  int64
}

func NewProgressReader(label string, total int64, reader io.Reader) *ProgressReader {
	return &ProgressReader{
		Reader: reader,
		label:  label,
		total:  total,
	}
}

func (pr *ProgressReader) Read(p []byte) (int, error) {
	n, err := pr.Reader.Read(p)

	pr.read += int64(n)

	percentage := float64(pr.read) / float64(pr.total) * 100
	log.Printf("\r%s: %.1f%%    ", pr.label, min(100, percentage))

	return n, err
}
