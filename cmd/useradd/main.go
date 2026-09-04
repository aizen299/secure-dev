// Command useradd creates a SecureOps user account.
//
// This exists to solve one problem: the first admin. Every account after it is
// created through the audited API by somebody who is already signed in
// (ADR 033 §6a).
//
// Why a command rather than an endpoint. An endpoint that works "while the
// users table is empty" puts the operation that mints an admin within reach of
// an unauthenticated caller, and "empty" is a race that reopens if every user
// is removed. Why not an environment variable: a password needed once would
// live permanently in .env and in every process environment that inherits it.
//
// The password is read from STDIN, never from a flag. A flag is visible in `ps`
// to every other process on the host and lands in shell history.
//
//	echo -n 'the-password' | useradd -email ada@example.com -role admin
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/aizen299/secure-dev/internal/audit"
	"github.com/aizen299/secure-dev/internal/config"
	"github.com/aizen299/secure-dev/internal/logging"
	"github.com/aizen299/secure-dev/internal/storage/postgres"
	"github.com/aizen299/secure-dev/internal/users"
)

func main() {
	email := flag.String("email", "", "the account's email address")
	role := flag.String("role", "viewer", "viewer, engineer, or admin")
	name := flag.String("name", "", "display name (optional)")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: useradd -email <address> [-role <role>] [-name <name>]\n\n")
		fmt.Fprintf(os.Stderr, "The password is read from stdin, never from a flag:\n")
		fmt.Fprintf(os.Stderr, "  echo -n 'the-password' | useradd -email ada@example.com -role admin\n\n")
		fmt.Fprintf(os.Stderr, "Creates the first admin. Every account after it goes through the\n")
		fmt.Fprintf(os.Stderr, "audited API (ADR 033).\n\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	logger := logging.New(os.Stdout, logging.Options{
		Level: slog.LevelInfo, Format: "text", Service: "secureops-useradd",
	})

	if err := run(logger, *email, *role, *name, os.Stdin); err != nil {
		// The error never carries the password: everything below either names a
		// field or reports a database failure.
		logger.Error("could not create the account", slog.String("error", err.Error()))
		os.Exit(1)
	}
}

func run(logger *slog.Logger, email, role, name string, stdin io.Reader) error {
	if strings.TrimSpace(email) == "" {
		return errors.New("-email is required")
	}
	parsedRole, ok := users.ParseRole(role)
	if !ok {
		return fmt.Errorf("role %q must be one of viewer, engineer, admin", role)
	}

	password, err := readPassword(stdin)
	if err != nil {
		return err
	}

	cfg, err := config.Load()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	db, err := postgres.Connect(ctx, postgres.Config{
		URL:      cfg.DatabaseURL,
		MaxConns: cfg.DBMaxConns,
	})
	if err != nil {
		return fmt.Errorf("connecting to the database: %w", err)
	}
	defer db.Close()

	store := users.NewStore(db.DB())

	// Recorded as the system acting on its own behalf, because at this point
	// there is nobody to attribute it to -- which is the whole reason this
	// command exists. Every later account creation names the admin who did it.
	actor := audit.Actor{Kind: audit.ActorSystem, Label: "useradd"}

	user, err := store.Create(ctx, users.NewUser{
		Email:       email,
		Password:    password,
		DisplayName: name,
		Role:        parsedRole,
	}, actor)
	switch {
	case errors.Is(err, users.ErrEmailTaken):
		return fmt.Errorf("an account already exists for %s", email)
	case err != nil:
		return err
	}

	// The id and the role, never the password. This output is routinely pasted
	// into a terminal somebody else can read.
	logger.Info("account created",
		slog.String("id", user.ID),
		slog.String("email", user.Email),
		slog.String("role", string(user.Role)))
	return nil
}

// readPassword takes the whole of stdin as the password.
//
// A trailing newline is stripped because `echo` adds one and almost nobody
// means it to be part of the password. Nothing else is trimmed: leading and
// interior whitespace are legitimate, and silently removing them would store a
// different password than the one typed.
func readPassword(stdin io.Reader) (string, error) {
	raw, err := io.ReadAll(io.LimitReader(stdin, 4096))
	if err != nil {
		return "", fmt.Errorf("reading the password from stdin: %w", err)
	}
	password := strings.TrimRight(string(raw), "\r\n")
	if password == "" {
		return "", errors.New("no password on stdin; pipe one in, for example: echo -n 'secret' | useradd -email you@example.com")
	}
	if len(password) < users.MinPasswordLength {
		return "", fmt.Errorf("password must be at least %d characters", users.MinPasswordLength)
	}
	return password, nil
}
