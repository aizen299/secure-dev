//go:build integration

package integration

import (
	"testing"

	"github.com/google/uuid"

	"github.com/aizen299/secure-dev/internal/audit"
	"github.com/aizen299/secure-dev/internal/projects"
)

// A project created through the store -- which writes an audit record -- must
// be deletable.
//
// This is the test that was missing. 0011 gave audit_logs.project_id
// ON DELETE SET NULL while its own triggers refused every UPDATE, so the
// cascade could never fire and any project with an audit record was
// permanently undeletable. Nothing caught it because every deletion test used
// a project inserted directly by a fixture, without the audit row the real
// creation path writes.
//
// So the audit record is the point of this test, not incidental setup.
func TestProjectWithAuditHistoryCanBeDeleted(t *testing.T) {
	pool := testPool(t)
	store := projects.NewStore(pool)

	project, err := store.Create(t.Context(), projects.NewProject{
		Name:        "Deletable",
		Slug:        "itest-deletable-" + uuid.NewString()[:8],
		Environment: projects.EnvDevelopment,
		Criticality: projects.CriticalityLow,
	}, audit.TokenActor("itest-deletion"))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	var auditRows int
	if err := pool.QueryRow(t.Context(),
		`SELECT count(*) FROM audit_logs WHERE project_id = $1`, project.ID,
	).Scan(&auditRows); err != nil {
		t.Fatalf("count audit rows: %v", err)
	}
	if auditRows == 0 {
		t.Fatal("creation wrote no audit record; this test would prove nothing")
	}

	// The statement that used to fail with "audit_logs is append-only".
	if _, err := pool.Exec(t.Context(), `DELETE FROM projects WHERE id = $1`, project.ID); err != nil {
		t.Fatalf("deleting a project with audit history: %v", err)
	}

	// The audit trail survives the deletion. This is stronger than the
	// original design intended: ON DELETE SET NULL would have erased the
	// project reference from every historical record (ADR 028).
	var surviving int
	if err := pool.QueryRow(t.Context(),
		`SELECT count(*) FROM audit_logs WHERE project_id = $1`, project.ID,
	).Scan(&surviving); err != nil {
		t.Fatalf("count surviving audit rows: %v", err)
	}
	if surviving != auditRows {
		t.Errorf("audit rows = %d after deletion, want %d: the trail must outlive its subject",
			surviving, auditRows)
	}
}

// The slug is denormalised so a record stays legible once its project is gone.
//
// An id alone proves something happened and says nothing about what, which is
// the difference between an audit trail that answers an investigation and one
// that merely exists.
func TestAuditRecordKeepsTheProjectSlugAfterDeletion(t *testing.T) {
	pool := testPool(t)
	store := projects.NewStore(pool)

	slug := "itest-named-" + uuid.NewString()[:8]
	project, err := store.Create(t.Context(), projects.NewProject{
		Name:        "Named",
		Slug:        slug,
		Environment: projects.EnvDevelopment,
		Criticality: projects.CriticalityLow,
	}, audit.TokenActor("itest-slug"))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	var recorded *string
	if err := pool.QueryRow(t.Context(),
		`SELECT project_slug FROM audit_logs WHERE project_id = $1 LIMIT 1`, project.ID,
	).Scan(&recorded); err != nil {
		t.Fatalf("read project_slug: %v", err)
	}
	if recorded == nil || *recorded != slug {
		t.Fatalf("project_slug = %v, want %q", recorded, slug)
	}

	if _, err := pool.Exec(t.Context(), `DELETE FROM projects WHERE id = $1`, project.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}

	// Still readable with the project gone.
	if err := pool.QueryRow(t.Context(),
		`SELECT project_slug FROM audit_logs WHERE project_id = $1 LIMIT 1`, project.ID,
	).Scan(&recorded); err != nil {
		t.Fatalf("read project_slug after deletion: %v", err)
	}
	if recorded == nil || *recorded != slug {
		t.Errorf("project_slug = %v after deletion, want %q", recorded, slug)
	}
}

// The append-only guarantee is unchanged. ADR 028 removed a foreign key; it
// carved no exception into the trigger, and an exception is what an attacker
// would read carefully.
func TestAuditLogsRemainAppendOnly(t *testing.T) {
	pool := testPool(t)

	if _, err := pool.Exec(t.Context(),
		`UPDATE audit_logs SET action = 'tampered' WHERE true`); err == nil {
		t.Error("audit_logs accepted an UPDATE")
	}
	if _, err := pool.Exec(t.Context(), `DELETE FROM audit_logs WHERE true`); err == nil {
		t.Error("audit_logs accepted a DELETE")
	}
}
