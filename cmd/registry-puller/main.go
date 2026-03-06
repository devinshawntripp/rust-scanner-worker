package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/yourorg/scanner-worker/internal/registry"
	"github.com/yourorg/scanner-worker/internal/s3"
)

// registry-puller is a standalone binary for K8s init containers.
// It pulls an OCI image from a registry, writes it as a tar,
// uploads the tar to S3, and exits so the scanner container can start.
//
// Required env vars:
//
//	REGISTRY_IMAGE    - full image ref (e.g. ghcr.io/org/app:v1)
//	SCAN_JOB_ID       - UUID of the scan job
//	UPLOADS_BUCKET    - S3 bucket for uploads
//	S3_ENDPOINT, S3_ACCESS_KEY, S3_SECRET_KEY, S3_USE_SSL
//
// Optional env vars:
//
//	REGISTRY_USERNAME - registry auth username
//	REGISTRY_TOKEN    - registry auth password/token
func main() {
	imageRef := requireEnv("REGISTRY_IMAGE")
	jobID := requireEnv("SCAN_JOB_ID")
	bucket := requireEnv("UPLOADS_BUCKET")

	var creds *registry.Credentials
	if u := os.Getenv("REGISTRY_USERNAME"); u != "" {
		creds = &registry.Credentials{
			Username: u,
			Password: os.Getenv("REGISTRY_TOKEN"),
		}
	}

	destTar := fmt.Sprintf("/scratch/%s/image.tar", jobID)
	if err := os.MkdirAll(fmt.Sprintf("/scratch/%s", jobID), 0755); err != nil {
		log.Fatalf("mkdir: %v", err)
	}

	log.Printf("pulling %s → %s", imageRef, destTar)
	if err := registry.PullToTar(imageRef, destTar, creds); err != nil {
		log.Fatalf("pull failed: %v", err)
	}

	info, _ := os.Stat(destTar)
	log.Printf("pulled %s (%d bytes)", imageRef, info.Size())

	s3c, err := s3.New(
		os.Getenv("S3_ENDPOINT"),
		os.Getenv("S3_ACCESS_KEY"),
		os.Getenv("S3_SECRET_KEY"),
		os.Getenv("S3_USE_SSL") == "true",
	)
	if err != nil {
		log.Fatalf("s3 init: %v", err)
	}

	objectKey := fmt.Sprintf("registry-pulls/%s/image.tar", jobID)
	log.Printf("uploading to s3://%s/%s", bucket, objectKey)
	if err := s3c.UploadFile(context.Background(), bucket, objectKey, destTar, "application/x-tar"); err != nil {
		log.Fatalf("s3 upload: %v", err)
	}

	log.Printf("done — s3://%s/%s ready for scanning", bucket, objectKey)
}

func requireEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		log.Fatalf("required env var %s not set", key)
	}
	return v
}
