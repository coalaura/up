package main

import (
	"io"

	"github.com/coalaura/progress"
)

type ProgressReader struct {
	io.Reader
	bar *progress.Bar
}

func NewProgressReader(label string, total int64, reader io.Reader) *ProgressReader {
	bar := progress.NewProgressBarWithTheme(label, total, progress.ThemeDots)

	bar.Start()

	return &ProgressReader{
		Reader: reader,
		bar:    bar,
	}
}

func (pr *ProgressReader) Read(p []byte) (int, error) {
	n, err := pr.Reader.Read(p)

	pr.bar.IncrementBy(int64(n))

	return n, err
}

func (pr *ProgressReader) Close() {
	pr.bar.Stop()
}
