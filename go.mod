module github.com/aizen299/secure-dev

go 1.27.0

require (
	github.com/go-chi/chi/v5 v5.3.2
	github.com/golang-migrate/migrate/v4 v4.19.1
	github.com/google/uuid v1.6.0
	github.com/jackc/pgx/v5 v5.10.0
	github.com/redis/go-redis/v9 v9.22.0
)

require (
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	github.com/lib/pq v1.10.9 // indirect
	go.uber.org/atomic v1.11.0 // indirect
	golang.org/x/sync v0.21.0 // indirect
	golang.org/x/sys v0.44.0 // indirect
	golang.org/x/text v0.39.0 // indirect
)

// The web app's node_modules contains unrelated Go source files that must never
// enter this module's build, test, or security-scan graph.
ignore ./apps/web/node_modules
