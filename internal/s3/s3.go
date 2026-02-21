package s3

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"

	minio "github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

type Client struct {
	mc *minio.Client
}

type ProgressFn func(bytesRead int64, totalBytes int64)

func New(endpoint, accessKey, secretKey string, useSSL bool) (*Client, error) {
	mc, err := minio.New(endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(accessKey, secretKey, ""),
		Secure: useSSL,
	})
	if err != nil { return nil, err }
	return &Client{mc: mc}, nil
}

func (c *Client) DownloadToFile(ctx context.Context, bucket, key, filePath string, onProgress ProgressFn) error {
	obj, err := c.mc.GetObject(ctx, bucket, key, minio.GetObjectOptions{})
	if err != nil { return err }
	defer obj.Close()

	var total int64
	if st, statErr := obj.Stat(); statErr == nil {
		total = st.Size
	}

	out, err := os.Create(filePath)
	if err != nil { return err }
	defer out.Close()

	const (
		bufSize          = 4 << 20  // 4 MiB
		progressMinBytes = 64 << 20 // 64 MiB
		progressMinTick  = 2 * time.Second
	)
	buf := make([]byte, bufSize)
	var copied int64
	var lastEmitBytes int64
	lastEmitAt := time.Now()

	emit := func(force bool) {
		if onProgress == nil {
			return
		}
		if !force {
			if copied-lastEmitBytes < progressMinBytes && time.Since(lastEmitAt) < progressMinTick {
				return
			}
		}
		lastEmitBytes = copied
		lastEmitAt = time.Now()
		onProgress(copied, total)
	}

	for {
		n, readErr := obj.Read(buf)
		if n > 0 {
			written, writeErr := out.Write(buf[:n])
			copied += int64(written)
			emit(false)
			if writeErr != nil {
				return writeErr
			}
			if written != n {
				return io.ErrShortWrite
			}
		}
		if readErr != nil {
			if readErr == io.EOF {
				emit(true)
				break
			}
			return fmt.Errorf("read s3 object: %w", readErr)
		}
	}
	return nil
}

func (c *Client) UploadFile(ctx context.Context, bucket, key, filePath string, contentType string) error {
	_, err := c.mc.FPutObject(ctx, bucket, key, filePath, minio.PutObjectOptions{
		ContentType: contentType,
	})
	return err
}
