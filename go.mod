module github.com/aizen299/secure-dev

go 1.27.0

require (
	github.com/go-chi/chi/v5 v5.3.2
	github.com/golang-migrate/migrate/v4 v4.19.1
	github.com/google/uuid v1.6.0
	github.com/jackc/pgx/v5 v5.10.0
	github.com/pb33f/libopenapi v0.38.7
	github.com/pb33f/libopenapi-validator v0.14.0
	github.com/redis/go-redis/v9 v9.22.0
	go.yaml.in/yaml/v4 v4.0.0-rc.6
)

require (
	github.com/bahlo/generic-list-go v0.2.0 // indirect
	github.com/basgys/goxml2json v1.1.1-0.20231018121955-e66ee54ceaad // indirect
	github.com/buger/jsonparser v1.1.2 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/go-openapi/jsonpointer v0.23.2 // indirect
	github.com/go-openapi/swag/jsonname v0.26.1 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	github.com/lib/pq v1.10.9 // indirect
	github.com/pb33f/jsonpath v0.8.2 // indirect
	github.com/pb33f/ordered-map/v2 v2.3.1 // indirect
	github.com/santhosh-tekuri/jsonschema/v6 v6.0.2 // indirect
	go.uber.org/atomic v1.11.0 // indirect
	golang.org/x/net v0.56.0 // indirect
	golang.org/x/sync v0.22.0 // indirect
	golang.org/x/sys v0.46.0 // indirect
	golang.org/x/text v0.39.0 // indirect
)

// The web app's node_modules contains unrelated Go source files that must never
// enter this module's build, test, or security-scan graph.
ignore ./apps/web/node_modules
