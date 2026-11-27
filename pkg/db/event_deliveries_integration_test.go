package db

import (
	"context"
	"database/sql"
	"os"
	"testing"
)

func TestEventDeliveriesMigrationIntegration(t *testing.T) {
	dsn := os.Getenv("FIDES_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set FIDES_TEST_DB_DSN to run the delivery migration test")
	}
	pool, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	tx, err := pool.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	// Isolate the pre-migration schema from the shared integration database.
	if _, err := tx.Exec(`CREATE TEMP TABLE integration_events (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(), status TEXT, attempts INT
	);
	SET LOCAL search_path = pg_temp;
	INSERT INTO integration_events (status, attempts) VALUES ('pending', 1), ('delivered', 2), ('dead', 3)`); err != nil {
		t.Fatal(err)
	}
	migration, err := migrationsFS.ReadFile("migrations/0028_event_deliveries.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(string(migration)); err != nil {
		t.Fatal(err)
	}
	var preserved, deliveries int
	err = tx.QueryRow(`SELECT count(*), (SELECT count(*) FROM integration_event_deliveries)
		FROM integration_events WHERE NOT deliveries_scheduled AND
		(status, attempts) IN (('pending', 1), ('delivered', 2), ('dead', 3))`).Scan(&preserved, &deliveries)
	if err != nil || preserved != 3 || deliveries != 0 {
		t.Fatalf("preserved=%d deliveries=%d err=%v", preserved, deliveries, err)
	}
}
