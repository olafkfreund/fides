package telemetry

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

type MetricsCollector struct {
	mu            sync.RWMutex
	requestCounts map[string]int64
	latencies     map[string]time.Duration
	totalRequests int64
	totalErrors   int64
	startTime     time.Time
	db            *sql.DB
}

var Instance = &MetricsCollector{
	requestCounts: make(map[string]int64),
	latencies:     make(map[string]time.Duration),
	startTime:     time.Now(),
}

func (c *MetricsCollector) SetDB(db *sql.DB) {
	c.db = db
}

type statusRecorder struct {
	http.ResponseWriter
	statusCode int
}

func (rec *statusRecorder) WriteHeader(code int) {
	rec.statusCode = code
	rec.ResponseWriter.WriteHeader(code)
}

func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Ignore static assets to avoid cluttering metrics
		if r.URL.Path == "/" || len(r.URL.Path) > 5 && r.URL.Path[:6] == "/_next" {
			next.ServeHTTP(w, r)
			return
		}

		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, statusCode: http.StatusOK}
		
		next.ServeHTTP(rec, r)
		
		duration := time.Since(start)
		
		atomic.AddInt64(&Instance.totalRequests, 1)
		if rec.statusCode >= 400 {
			atomic.AddInt64(&Instance.totalErrors, 1)
		}

		key := fmt.Sprintf("%s %s %d", r.Method, r.URL.Path, rec.statusCode)
		
		Instance.mu.Lock()
		Instance.requestCounts[key]++
		Instance.latencies[key] += duration
		Instance.mu.Unlock()
	})
}

// PrometheusExporter returns metrics in Prometheus text format
func (c *MetricsCollector) PrometheusExporter(w http.ResponseWriter, r *http.Request) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")

	fmt.Fprintf(w, "# HELP fides_http_requests_total Total number of HTTP requests processed.\n")
	fmt.Fprintf(w, "# TYPE fides_http_requests_total counter\n")
	fmt.Fprintf(w, "fides_http_requests_total{type=\"all\"} %d\n", atomic.LoadInt64(&c.totalRequests))
	fmt.Fprintf(w, "fides_http_requests_total{type=\"error\"} %d\n", atomic.LoadInt64(&c.totalErrors))

	for key, count := range c.requestCounts {
		fmt.Fprintf(w, "fides_http_requests_by_route_total{%s} %d\n", keyToLabels(key), count)
	}

	fmt.Fprintf(w, "\n# HELP fides_uptime_seconds Uptime of the Fides server in seconds.\n")
	fmt.Fprintf(w, "# TYPE fides_uptime_seconds gauge\n")
	fmt.Fprintf(w, "fides_uptime_seconds %d\n", int(time.Since(c.startTime).Seconds()))

	// Go Runtime metrics
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	fmt.Fprintf(w, "\n# HELP go_memstats_alloc_bytes Number of bytes allocated and still in use.\n")
	fmt.Fprintf(w, "# TYPE go_memstats_alloc_bytes gauge\n")
	fmt.Fprintf(w, "go_memstats_alloc_bytes %d\n", m.Alloc)

	fmt.Fprintf(w, "# HELP go_goroutines_total Total number of running goroutines.\n")
	fmt.Fprintf(w, "# TYPE go_goroutines_total gauge\n")
	fmt.Fprintf(w, "go_goroutines_total %d\n", runtime.NumGoroutine())

	// Database metrics
	if c.db != nil {
		stats := c.db.Stats()
		fmt.Fprintf(w, "\n# HELP fides_db_open_connections Open database connections.\n")
		fmt.Fprintf(w, "# TYPE fides_db_open_connections gauge\n")
		fmt.Fprintf(w, "fides_db_open_connections %d\n", stats.OpenConnections)

		fmt.Fprintf(w, "# HELP fides_db_in_use_connections Database connections currently in use.\n")
		fmt.Fprintf(w, "# TYPE fides_db_in_use_connections gauge\n")
		fmt.Fprintf(w, "fides_db_in_use_connections %d\n", stats.InUse)
	}
}

// JSONExporter returns metrics in JSON format for the internal dashboard
func (c *MetricsCollector) JSONExporter(w http.ResponseWriter, r *http.Request) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	dbOpen := 0
	dbInUse := 0
	dbIdle := 0
	if c.db != nil {
		stats := c.db.Stats()
		dbOpen = stats.OpenConnections
		dbInUse = stats.InUse
		dbIdle = stats.Idle
	}

	totalReq := atomic.LoadInt64(&c.totalRequests)
	totalErr := atomic.LoadInt64(&c.totalErrors)
	errorRate := 0.0
	if totalReq > 0 {
		errorRate = (float64(totalErr) / float64(totalReq)) * 100
	}

	// Calculate average latency
	var totalDuration time.Duration
	for _, lat := range c.latencies {
		totalDuration += lat
	}
	avgLatencyMs := 0.0
	if totalReq > 0 {
		avgLatencyMs = float64(totalDuration.Milliseconds()) / float64(totalReq)
	}

	statsMap := map[string]interface{}{
		"total_requests":     totalReq,
		"total_errors":       totalErr,
		"error_rate":         errorRate,
		"average_latency_ms": avgLatencyMs,
		"uptime_seconds":     int(time.Since(c.startTime).Seconds()),
		"db_connections": map[string]interface{}{
			"open":   dbOpen,
			"in_use": dbInUse,
			"idle":   dbIdle,
		},
		"memory_allocated_mb": float64(m.Alloc) / (1024 * 1024),
		"goroutines":          runtime.NumGoroutine(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(statsMap)
}

func keyToLabels(key string) string {
	// key format: "METHOD PATH STATUS"
	var method, path, status string
	fmt.Sscanf(key, "%s %s %s", &method, &path, &status)
	return fmt.Sprintf("method=\"%s\",path=\"%s\",status=\"%s\"", method, path, status)
}
