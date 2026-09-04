package audit

import (
	"errors"
	"testing"
)

// The kind ADR 006, ADR 022, ADR 024 and ADR 029 each recorded as missing.
//
// Until this existed, "who dismissed this finding?" was answerable only to the
// granularity of a credential label, and an action taken through the dashboard
// was recorded against the dashboard.
func TestUserActorNamesAPerson(t *testing.T) {
	actor, err := UserActor("11111111-2222-4333-8444-555555555555")
	if err != nil {
		t.Fatalf("UserActor: %v", err)
	}
	if actor.Kind != ActorUser {
		t.Errorf("kind = %q, want %q", actor.Kind, ActorUser)
	}
	if actor.Label != "11111111-2222-4333-8444-555555555555" {
		t.Errorf("label = %q, want the user id", actor.Label)
	}
}

// An empty id is refused, never defaulted.
//
// "user" with no user is a claim of attribution that is not true, and it would
// be indistinguishable in the trail from a real one.
func TestUserActorRefusesAnEmptyID(t *testing.T) {
	for _, id := range []string{"", "   ", "\t"} {
		if _, err := UserActor(id); !errors.Is(err, ErrInvalidEntry) {
			t.Errorf("UserActor(%q) err = %v, want ErrInvalidEntry", id, err)
		}
	}
}

// The label is the id and not the email, deliberately.
//
// An audit record outlives the account it names: a person can be renamed and a
// person can leave. A record pointing at a mutable value is a record whose
// subject can be changed after the fact.
func TestUserActorDoesNotCarryAnEmail(t *testing.T) {
	actor, err := UserActor("a-user-id")
	if err != nil {
		t.Fatalf("UserActor: %v", err)
	}
	if actor.Label == "ada@example.com" {
		t.Error("the actor label is an email; it must be the stable id")
	}
}

// The three kinds stay distinguishable, which is the point of having a kind at
// all: a reader of the trail must be able to tell a person from a credential
// from the system acting on its own behalf.
func TestTheActorKindsAreDistinct(t *testing.T) {
	token := TokenActor("ci-runner")
	user, err := UserActor("a-user-id")
	if err != nil {
		t.Fatalf("UserActor: %v", err)
	}

	if token.Kind == user.Kind {
		t.Fatal("a token and a person share an actor kind")
	}
	for _, k := range []ActorKind{ActorTokenLabel, ActorUser, ActorSystem} {
		if k == "" {
			t.Error("an actor kind is empty")
		}
	}
}
