//go:build integration

package integration

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/aizen299/secure-dev/internal/audit"
	"github.com/aizen299/secure-dev/internal/projects"
	"github.com/aizen299/secure-dev/internal/users"
)

// A bad project id in a membership change is the caller's mistake, not ours.
//
// Both a malformed uuid and a well-formed id for a project that does not exist
// used to reach the API as a 500 with the message "internal error" -- which
// tells an administrator nothing about a mistake they made and can fix. Found
// by driving the Access screen's membership editor against the live stack.
//
// The database still enforces the relationship; what changed is how the failure
// is reported.
// testActor stands in for whoever made the change. These tests are about which
// error comes back, not about attribution.
var testActor = audit.Actor{Kind: audit.ActorSystem, Label: "integration-test"}

// randomSuffix keeps emails and slugs unique across runs against one database.
func randomSuffix() string { return uuid.NewString()[:8] }

// seedUser creates a throwaway account and removes it when the test ends.
//
// The cleanup matters more here than for other fixtures: an account shows up on
// the Access screen, so a suite that leaves them behind fills a real operator's
// roster with test users. Raw SQL because the store has no delete -- §17 keeps
// accounts for their audit trail, which is right for people and wrong for
// fixtures.
func seedUser(t *testing.T, store *users.Store, pool *pgxpool.Pool, role users.Role) users.User {
	t.Helper()
	user, err := store.Create(t.Context(), users.NewUser{
		Email:    "itest-" + randomSuffix() + "@example.com",
		Password: "a-long-enough-password",
		Role:     role,
	}, testActor)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	t.Cleanup(func() {
		if _, err := pool.Exec(context.Background(),
			`DELETE FROM users WHERE id = $1`, user.ID); err != nil {
			t.Logf("cleanup user %s: %v", user.ID, err)
		}
	})
	return user
}

func TestMembershipRejectsAnUnknownProject(t *testing.T) {
	pool := testPool(t)
	userStore := users.NewStore(pool)

	user := seedUser(t, userStore, pool, users.RoleViewer)

	for name, id := range map[string]string{
		"a malformed uuid":            "not-a-uuid",
		"a project that is not there": "aa000000-0000-4000-8000-999999999999",
	} {
		t.Run(name, func(t *testing.T) {
			err := userStore.SetMembership(t.Context(), user.ID, []string{id}, testActor)
			if !errors.Is(err, users.ErrUnknownProject) {
				t.Errorf("SetMembership(%q) = %v, want ErrUnknownProject so the API answers 400", id, err)
			}
		})
	}
}

// One bad id grants nothing, rather than granting the part that parsed.
//
// SetMembership replaces the whole set inside one transaction. A partial apply
// would leave an administrator believing they granted three projects when the
// person reaches one -- a scope that quietly differs from the screen that set
// it.
func TestABadProjectIdGrantsNothing(t *testing.T) {
	pool := testPool(t)
	userStore := users.NewStore(pool)
	projectStore := projects.NewStore(pool)

	good, err := projectStore.Create(t.Context(), projects.NewProject{
		Name: "Grantable " + randomSuffix(), Environment: projects.EnvDevelopment,
		Criticality: projects.CriticalityLow,
	}, testActor)
	if err != nil {
		t.Fatalf("create project: %v", err)
	}

	user := seedUser(t, userStore, pool, users.RoleEngineer)

	err = userStore.SetMembership(t.Context(), user.ID,
		[]string{good.ID, "aa000000-0000-4000-8000-999999999999"}, testActor)
	if err == nil {
		t.Fatal("SetMembership accepted an unknown project id")
	}

	got, err := userStore.MembershipOf(t.Context(), user.ID)
	if err != nil {
		t.Fatalf("membership: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("membership = %v, want none: a refused batch must grant nothing", got)
	}
}
