package main

import (
	"context"
	"database/sql"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"fides/pkg/ai"
	"fides/pkg/api"
	"fides/pkg/storage"

	_ "github.com/lib/pq"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	dbDSN := os.Getenv("DB_DSN")
	if dbDSN == "" {
		log.Fatal("DB_DSN environment variable is required (e.g. \"host=... user=... password=... dbname=fides sslmode=verify-full\"). " +
			"Refusing to start with an embedded credential/default.")
	}

	log.Printf("Connecting to database...")
	db, err := sql.Open("postgres", dbDSN)
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	if err := db.Ping(); err != nil {
		log.Fatalf("Failed to establish database connection ping: %v", err)
	}

	var store storage.StorageBackend
	storageDriver := os.Getenv("STORAGE_DRIVER")
	if storageDriver == "s3" {
		region := os.Getenv("AWS_REGION")
		if region == "" {
			region = "eu-west-2"
		}
		log.Printf("Initializing Fides S3 storage in region %s...", region)
		store, err = storage.NewS3Storage(context.Background(), region)
		if err != nil {
			log.Fatalf("Failed to initialize S3 storage: %v", err)
		}
	} else {
		storageDir := os.Getenv("STORAGE_LOCAL_DIR")
		if storageDir == "" {
			storageDir = "./data/evidence"
		}
		log.Printf("Initializing Fides local storage at %s...", storageDir)
		store, err = storage.NewLocalStorage(storageDir)
		if err != nil {
			log.Fatalf("Failed to initialize storage: %v", err)
		}
	}

	// Dynamic LLM provider selection
	var llm ai.LLMClient
	aiProvider := os.Getenv("AI_PROVIDER")
	if aiProvider == "ollama" {
		endpoint := os.Getenv("AI_OLLAMA_ENDPOINT")
		if endpoint == "" {
			endpoint = "http://localhost:11434"
		}
		model := os.Getenv("AI_MODEL")
		if model == "" {
			model = "llama3:8b"
		}
		log.Printf("Connecting to Ollama provider (endpoint: %s, model: %s)...", endpoint, model)
		llm = ai.NewOllamaClient(endpoint, model)
	} else if aiProvider == "llamacpp" {
		endpoint := os.Getenv("AI_LLAMACPP_ENDPOINT")
		if endpoint == "" {
			endpoint = "http://localhost:8080"
		}
		log.Printf("Connecting to llama.cpp provider (endpoint: %s)...", endpoint)
		llm = ai.NewLlamaCppClient(endpoint)
	} else if aiProvider == "gemini" {
		apiKey := os.Getenv("GEMINI_API_KEY")
		model := os.Getenv("AI_MODEL")
		log.Printf("Connecting to Gemini provider (model: %s)...", model)
		llm = ai.NewGeminiClient(apiKey, model)
	}

	// Initialize Fides Server
	server := api.NewServer(db, store, llm)

	srv := &http.Server{
		Addr:              ":" + port,
		Handler:           server.Routes(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      120 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20, // 1 MiB
	}

	// Graceful shutdown on SIGINT/SIGTERM.
	go func() {
		log.Printf("Fides API Server running on port %s...", port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server failed: %v", err)
		}
	}()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()

	log.Printf("Shutdown signal received, draining connections...")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("HTTP shutdown error: %v", err)
	}
}
