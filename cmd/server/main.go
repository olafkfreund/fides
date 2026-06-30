package main

import (
	"context"
	"database/sql"
	"log"
	"net/http"
	"os"

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
		dbDSN = "host=localhost port=5433 user=fides_user password=fides_password_secure dbname=fides sslmode=disable"
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

	storageDir := os.Getenv("STORAGE_LOCAL_DIR")
	if storageDir == "" {
		storageDir = "./data/evidence"
	}

	log.Printf("Initializing Fides local storage at %s...", storageDir)
	store, err := storage.NewLocalStorage(storageDir)
	if err != nil {
		log.Fatalf("Failed to initialize storage: %v", err)
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
		Addr:    ":" + port,
		Handler: server.Routes(),
	}

	log.Printf("Fides API Server running on port %s...", port)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Server failed: %v", err)
	}
}

func shutdown(ctx context.Context, srv *http.Server) {
	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("HTTP shutdown error: %v", err)
	}
}
