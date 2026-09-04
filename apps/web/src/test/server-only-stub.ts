/**
 * A no-op stand-in for the `server-only` package, used by tests only.
 *
 * `server-only` throws on import unless it is resolved under React's
 * `react-server` condition. That is the whole point of it: a client component
 * that imports a server module fails the build rather than shipping a secret.
 *
 * The guard still does its job -- `next build` resolves the real package, and
 * `make check` runs that build. What is replaced here is only the runtime
 * throw, so a test may import the modules the guard protects. Without this,
 * `lib/session.ts` -- the most security-relevant file in the app -- would be
 * the one file that cannot be tested.
 */
export {};
