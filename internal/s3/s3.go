package s3

import (
	"context"
	"io"
	"os"

	minio "github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

type Client struct {
	mc *minio.Client
}

func New(endpoint, accessKey, secretKey string, useSSL bool) (*Client, error) {
	mc, err := minio.New(endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(accessKey, secretKey, ""),
		Secure: useSSL,
	})
	if err != nil { return nil, err }
	return &Client{mc: mc}, nil
}

func (c *Client) DownloadToFile(ctx context.Context, bucket, key, filePath string) error {
	obj, err := c.mc.GetObject(ctx, bucket, key, minio.GetObjectOptions{})
	if err != nil { return err }
	defer obj.Close()

	out, err := os.Create(filePath)
	if err != nil { return err }
	defer out.Close()

	_, err = io.Copy(out, obj)
	return err
}

func (c *Client) UploadFile(ctx context.Context, bucket, key, filePath string, contentType string) error {
	_, err := c.mc.FPutObject(ctx, bucket, key, filePath, minio.PutObjectOptions{
		ContentType: contentType,
	})
	return err
}
